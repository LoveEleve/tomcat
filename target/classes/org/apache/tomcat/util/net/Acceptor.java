/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.res.StringManager;

public class Acceptor<U> implements Runnable {

    private static final Log log = LogFactory.getLog(Acceptor.class);
    private static final StringManager sm = StringManager.getManager(Acceptor.class);

    private static final int INITIAL_ERROR_DELAY = 50;
    private static final int MAX_ERROR_DELAY = 1600;
    // U -> SocketChannel
    private final AbstractEndpoint<?,U> endpoint;
    private String threadName;
    /*
     * Tracked separately rather than using endpoint.isRunning() as calls to
     * endpoint.stop() and endpoint.start() in quick succession can cause the
     * acceptor to continue running when it should terminate.
     */
    private volatile boolean stopCalled = false;
    private final CountDownLatch stopLatch = new CountDownLatch(1);
    protected volatile AcceptorState state = AcceptorState.NEW;


    public Acceptor(AbstractEndpoint<?,U> endpoint) {
        this.endpoint = endpoint; // 持有Endpoint引用
    }


    public final AcceptorState getState() {
        return state;
    }


    final void setThreadName(final String threadName) {
        this.threadName = threadName;
    }


    final String getThreadName() {
        return threadName;
    }


    @SuppressWarnings("deprecation")
    @Override
    public void run() {

        int errorDelay = 0;
        long pauseStart = 0;

        try {
            // Loop until we receive a shutdown command
            while (!stopCalled) {

                // Loop if endpoint is paused.
                // There are two likely scenarios here.
                // The first scenario is that Tomcat is shutting down. In this
                // case - and particularly for the unit tests - we want to exit
                // this loop as quickly as possible. The second scenario is a
                // genuine pause of the connector. In this case we want to avoid
                // excessive CPU usage.
                // Therefore, we start with a tight loop but if there isn't a
                // rapid transition to stop then sleeps are introduced.
                // < 1ms       - tight loop
                // 1ms to 10ms - 1ms sleep
                // > 10ms      - 10ms sleep
                /*
                    这里的逻辑默认不会执行,正常运行时endpoint.isPaused()为false
                    执行的时机在: 优雅停机 / 手动暂停 / 配置热更新
                    核心目的在于，避免新连接进入即将关闭的服务器
                    ps:这里的逻辑暂时不了解,目前只关注核心逻辑
                 */
                while (endpoint.isPaused() && !stopCalled) {
                    if (state != AcceptorState.PAUSED) {
                        pauseStart = System.nanoTime();
                        // Entered pause state
                        state = AcceptorState.PAUSED;
                    }
                    if ((System.nanoTime() - pauseStart) > 1_000_000) {
                        // Paused for more than 1ms
                        try {
                            if ((System.nanoTime() - pauseStart) > 10_000_000) {
                                Thread.sleep(10);
                            } else {
                                Thread.sleep(1);
                            }
                        } catch (InterruptedException e) {
                            // Ignore
                        }
                    }
                }

                if (stopCalled) {
                    break;
                }
                state = AcceptorState.RUNNING;

                try {
                    //if we have reached max connections, wait
                    // 申请连接 - 默认最大连接数为8192,如果这里申请失败,那么Acceptor线程会阻塞(此时无法再接受新的连接)
                    // 这里提出一个问题：什么时候关闭连接呢？
                    endpoint.countUpOrAwaitConnection();

                    // Endpoint might have been paused while waiting for latch
                    // If that is the case, don't accept new connections
                    if (endpoint.isPaused()) {
                        continue;
                    }

                    U socket = null;
                    try {
                        // Accept the next incoming connection from the server
                        // socket
                        /*
                            接受新连接,这里就是调用accept()来阻塞接受的,并且ServerSock是被设置为了阻塞的(serverSock.configureBlocking(true))
                            问题：为什么Acceptor线程没有使用Selector呢？而是直接使用accept()呢? 按照Netty的做法,这里应该是可读事件，然后调用accept()
                            类型的问题：在Netty中,使用了BossGroup和WorkerGroup,当BossGroup = 1时,和这里的Acceptor是一样的，
                            但是为什么在Netty中即使使用一个线程来接受新连接,也要使用Selector呢？
                                - 在这里,其实对于网络连接来说,什么是瓶颈呢？
                                  其实连接的接收并不耗时,真正耗时的在于后续的持续IO操作(读/写操作)以及业务处理(比如Http解析)
                                - 那为什么Nett中也使用了Selector呢？
                                  大概的原因是因为Netty中的一个线程(EventLoop)不仅仅需要接受新连接,在tomcat中,没有连接的话,那么Acceptor线程就阻塞了，
                                  但是在Netty中,一个EventLoop还可能需要执行定时任务和异步任务,必须是非阻塞的
                         */
                        // 这里
                        socket = endpoint.serverSocketAccept();
                    } catch (Exception ioe) {
                        // We didn't get a socket
                        endpoint.countDownConnection();
                        if (endpoint.isRunning()) {
                            // Introduce delay if necessary
                            errorDelay = handleExceptionWithDelay(errorDelay);
                            // re-throw
                            throw ioe;
                        } else {
                            break;
                        }
                    }
                    // Successful accept, reset the error delay
                    errorDelay = 0;

                    // Configure the socket
                    /*
                        配置socket(客户端),将socket交给Poller线程来处理
                        核心方法:setSocketOptions()
                     */
                    if (!stopCalled && !endpoint.isPaused()) {
                        // setSocketOptions() will hand the socket off to
                        // an appropriate processor if successful
                        if (!endpoint.setSocketOptions(socket)) {
                            endpoint.closeSocket(socket);
                        }
                    } else {
                        endpoint.destroySocket(socket);
                    }
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    String msg = sm.getString("endpoint.accept.fail");
                    // APR specific.
                    // Could push this down but not sure it is worth the trouble.
                    if (t instanceof org.apache.tomcat.jni.Error) {
                        org.apache.tomcat.jni.Error e = (org.apache.tomcat.jni.Error) t;
                        if (e.getError() == 233) {
                            // Not an error on HP-UX so log as a warning
                            // so it can be filtered out on that platform
                            // See bug 50273
                            log.warn(msg, t);
                        } else {
                            log.error(msg, t);
                        }
                    } else {
                            log.error(msg, t);
                    }
                }
            }
        } finally {
            stopLatch.countDown();
        }
        state = AcceptorState.ENDED;
    }


    /**
     * Signals the Acceptor to stop, waiting at most 10 seconds for the stop to
     * complete before returning. If the stop does not complete in that time a
     * warning will be logged.
     *
     * @deprecated This method will be removed in Tomcat 10.1.x onwards.
     *             Use {@link #stop(int)} instead.
     */
    @Deprecated
    public void stop() {
        stop(10);
    }


    /**
     * Signals the Acceptor to stop, optionally waiting for that stop process
     * to complete before returning. If a wait is requested and the stop does
     * not complete in that time a warning will be logged.
     *
     * @param waitSeconds The time to wait in seconds. Use a value less than
     *                    zero for no wait.
     */
    public void stop(int waitSeconds) {
        stopCalled = true;
        if (waitSeconds > 0) {
            try {
                if (!stopLatch.await(waitSeconds, TimeUnit.SECONDS)) {
                   log.warn(sm.getString("acceptor.stop.fail", getThreadName()));
                }
            } catch (InterruptedException e) {
                log.warn(sm.getString("acceptor.stop.interrupted", getThreadName()), e);
            }
        }
    }


    /**
     * Handles exceptions where a delay is required to prevent a Thread from
     * entering a tight loop which will consume CPU and may also trigger large
     * amounts of logging. For example, this can happen if the ulimit for open
     * files is reached.
     *
     * @param currentErrorDelay The current delay being applied on failure
     * @return  The delay to apply on the next failure
     */
    protected int handleExceptionWithDelay(int currentErrorDelay) {
        // Don't delay on first exception
        if (currentErrorDelay > 0) {
            try {
                Thread.sleep(currentErrorDelay);
            } catch (InterruptedException e) {
                // Ignore
            }
        }

        // On subsequent exceptions, start the delay at 50ms, doubling the delay
        // on every subsequent exception until the delay reaches 1.6 seconds.
        if (currentErrorDelay == 0) {
            return INITIAL_ERROR_DELAY;
        } else if (currentErrorDelay < MAX_ERROR_DELAY) {
            return currentErrorDelay * 2;
        } else {
            return MAX_ERROR_DELAY;
        }
    }


    public enum AcceptorState {
        NEW, RUNNING, PAUSED, ENDED
    }
}
