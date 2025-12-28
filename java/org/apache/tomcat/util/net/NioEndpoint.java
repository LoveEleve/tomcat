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

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.Channel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.CompletionHandler;
import java.nio.channels.FileChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLEngine;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.collections.SynchronizedQueue;
import org.apache.tomcat.util.collections.SynchronizedStack;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.compat.JrePlatform;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.jsse.JSSESupport;

/**
 * NIO endpoint.
 *
 * @author Mladen Turk
 */
public class NioEndpoint extends AbstractJsseEndpoint<NioChannel,SocketChannel> {


    // -------------------------------------------------------------- Constants


    private static final Log log = LogFactory.getLog(NioEndpoint.class);
    private static final Log logCertificate = LogFactory.getLog(NioEndpoint.class.getName() + ".certificate");
    private static final Log logHandshake = LogFactory.getLog(NioEndpoint.class.getName() + ".handshake");


    public static final int OP_REGISTER = 0x100; //register interest op

    // ----------------------------------------------------------------- Fields

    /**
     * Server socket "pointer".
     */
    private volatile ServerSocketChannel serverSock = null;

    /**
     * Stop latch used to wait for poller stop
     */
    private volatile CountDownLatch stopLatch = null;

    /**
     * Cache for poller events
     */
    private SynchronizedStack<PollerEvent> eventCache;

    /**
     * Bytebuffer cache, each channel holds a set of buffers (two, except for SSL holds four)
     */
    private SynchronizedStack<NioChannel> nioChannels;

    private SocketAddress previousAcceptedSocketRemoteAddress = null;
    private long previousAcceptedSocketNanoTime = 0;


    // ------------------------------------------------------------- Properties

    /**
     * Use System.inheritableChannel to obtain channel from stdin/stdout.
     */
    private boolean useInheritedChannel = false;
    public void setUseInheritedChannel(boolean useInheritedChannel) { this.useInheritedChannel = useInheritedChannel; }
    public boolean getUseInheritedChannel() { return useInheritedChannel; }


    /**
     * Priority of the poller threads.
     */
    private int pollerThreadPriority = Thread.NORM_PRIORITY;
    public void setPollerThreadPriority(int pollerThreadPriority) { this.pollerThreadPriority = pollerThreadPriority; }
    public int getPollerThreadPriority() { return pollerThreadPriority; }


    /**
     * NO-OP.
     *
     * @param pollerThreadCount Unused
     *
     * @deprecated Will be removed in Tomcat 10.
     */
    @Deprecated
    public void setPollerThreadCount(int pollerThreadCount) { }
    /**
     * Always returns 1.
     *
     * @return Always 1.
     *
     * @deprecated Will be removed in Tomcat 10.
     */
    @Deprecated
    public int getPollerThreadCount() { return 1; }

    private long selectorTimeout = 1000;
    public void setSelectorTimeout(long timeout) { this.selectorTimeout = timeout;}
    public long getSelectorTimeout() { return this.selectorTimeout; }

    /**
     * The socket poller.
     */
    private Poller poller = null;
    /**
     * Not used.
     *
     * @return The poller
     *
     * @deprecated Will be removed in Tomcat 9.
     */
    @Deprecated
    public Poller getPoller0() {
        return poller;
    }


    /**
     * Is deferAccept supported?
     */
    @Override
    public boolean getDeferAccept() {
        // Not supported
        return false;
    }


    // --------------------------------------------------------- Public Methods

    /**
     * Number of keep-alive sockets.
     *
     * @return The number of sockets currently in the keep-alive state waiting
     *         for the next request to be received on the socket
     */
    public int getKeepAliveCount() {
        if (poller == null) {
            return 0;
        } else {
            return poller.getKeyCount();
        }
    }


    // ----------------------------------------------- Public Lifecycle Methods

    /**
     * Initialize the endpoint.
     */
    @Override
    public void bind() throws Exception {
        // 初始化服务器套接字
        initServerSocket();
        // 创建停止闩锁（用于优雅停机）
        /*
            CountDownLatch countDownLatch = new CountDownLatch(1);
            countDownLatch.countDown(); // 将内部的计数-1(最后一个置为0的线程负责唤醒await()阻塞的线程)
            countDownLatch.await(); / /如果计数不为0,那么将会阻塞等待
            这个stopLatch就是用来专门等待Poller线程停止的
        */
        setStopLatch(new CountDownLatch(1));

        // Initialize SSL if needed
        initialiseSsl();
    }

    // Separated out to make it easier for folks that extend NioEndpoint to
    // implement custom [server]sockets
    protected void initServerSocket() throws Exception {
        if (getUseInheritedChannel()) { // 这里默认为false
            // Retrieve the channel provided by the OS
            Channel ic = System.inheritedChannel();
            if (ic instanceof ServerSocketChannel) {
                serverSock = (ServerSocketChannel) ic;
            }
            if (serverSock == null) {
                throw new IllegalArgumentException(sm.getString("endpoint.init.bind.inherited"));
            }
        } else { // 这里为默认逻辑
            // 1.创建ServerSocketChannel(服务端)
            serverSock = ServerSocketChannel.open();
            // 2.设置 socket 属性 - 这个 socketProperties 属性对象很重要
            /*
                问题:如何自定义这个socketProperties配置呢？
                    1.在server.xml的<Connector/>中配置
                    2.在SpringBoot中可以直接在xxx.properties/xxx.yml中配置
                      或者可以通过如下方式配置:
                    --
                        @Configuration
                        @Profile("prod")
                        public class TomcatConfig {
                            @Bean
                            public WebServerFactoryCustomizer<TomcatServletWebServerFactory> prodTomcatCustomizer() {
                                return factory -> {
                                    factory.addConnectorCustomizers(connector -> {
                                        Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();

                                        // 生产环境特殊配置
                                        protocol.setProperty("socket.directSslBuffer", "true");
                                        protocol.setProperty("socket.bufferPool", "500");
                                    });
                                };
                            }
                        }
            */
            socketProperties.setProperties(serverSock.socket());
            // 3.创建绑定地址
            InetSocketAddress addr = new InetSocketAddress(getAddress(), getPortWithOffset());
            // 4.绑定地址
            serverSock.socket().bind(addr,getAcceptCount());
        }
        // 设置为阻塞模式(为什么要设置为阻塞模式呢?)
        serverSock.configureBlocking(true); //mimic APR behavior
    }


    /**
     * Start the NIO endpoint, creating acceptor, poller threads.
     */
    @Override
    public void startInternal() throws Exception {

        if (!running) {
            running = true;
            paused = false;
            // ========== 1. 初始化对象缓存池（性能优化）==========
            /*
                对象缓存池:
                    - Processor 缓存池: 用于缓存 Processor 对象
                        - Processor对象 : HTTP协议处理器对象
                    ========>
                    - Event 缓存池: 用于缓存 Event 对象
                        - PollerEvent对象 : 用于将Socket注册到 Poller的 Selector
                        常见的用法:
                        // Acceptor 接收到新连接后
                        PollerEvent event = eventCache.pop();  // 从缓存获取
                        if (event == null) {
                            event = new PollerEvent(socket, OP_READ);
                        }
                        poller.addEvent(event);  // 提交给 Poller
                    ========>
                    - Buffer 缓存池: 用于缓存 Buffer 对象
                        - NioChannel对象 : 缓存 NioChannel对象及其关联的ByteBuffer - (NioChannel封装了SocketChannel和读写缓存区)
                            class NioChannel {
                                SocketChannel sc;          // 原生 NIO Channel
                                ByteBuffer readBuffer;     // 读缓冲区
                                ByteBuffer writeBuffer;    // 写缓冲区
                            }
            */
            if (socketProperties.getProcessorCache() != 0) {
                processorCache = new SynchronizedStack<>(SynchronizedStack.DEFAULT_SIZE,
                        socketProperties.getProcessorCache());
            }
            if (socketProperties.getEventCache() != 0) {
                eventCache = new SynchronizedStack<>(SynchronizedStack.DEFAULT_SIZE,
                        socketProperties.getEventCache());
            }
            if (socketProperties.getBufferPool() != 0) {
                nioChannels = new SynchronizedStack<>(SynchronizedStack.DEFAULT_SIZE,
                        socketProperties.getBufferPool());
            }

            // Create worker collection
            // ========== 2. 创建工作线程池 ==========
            if (getExecutor() == null) {
                createExecutor(); // 创建处理请求的线程池
            }
            // ========== 3. 初始化连接限流器 ==========
            initializeConnectionLatch(); // 限制最大并发连接数

            // ========== 4. 创建并启动 Poller 线程 ==========
            // Start poller thread
            poller = new Poller(); // 创建Poller对象(Poller对象本身就是一个Runnable)
            Thread pollerThread = new Thread(poller, getName() + "-Poller"); // 启动事件轮询线程
            pollerThread.setPriority(threadPriority);
            pollerThread.setDaemon(true);
            pollerThread.start(); // 启动 - 开始执行run()方法

            // ========== 5. 启动 Acceptor 线程 ==========
            startAcceptorThread(); // 启动接收连接的线程
        }
    }


    /**
     * Stop the endpoint. This will cause all processing threads to stop.
     */
    @Override
    public void stopInternal() {
        if (!paused) {
            pause();
        }
        if (running) {
            running = false;
            acceptor.stop(10);
            if (poller != null) {
                poller.destroy();
                poller = null;
            }
            try {
                if (!getStopLatch().await(selectorTimeout + 100, TimeUnit.MILLISECONDS)) {
                    log.warn(sm.getString("endpoint.nio.stopLatchAwaitFail"));
                }
            } catch (InterruptedException e) {
                log.warn(sm.getString("endpoint.nio.stopLatchAwaitInterrupted"), e);
            }
            shutdownExecutor();
            if (eventCache != null) {
                eventCache.clear();
                eventCache = null;
            }
            if (nioChannels != null) {
                NioChannel socket;
                while ((socket = nioChannels.pop()) != null) {
                    socket.free();
                }
                nioChannels = null;
            }
            if (processorCache != null) {
                processorCache.clear();
                processorCache = null;
            }
        }
    }


    /**
     * Deallocate NIO memory pools, and close server socket.
     */
    @Override
    public void unbind() throws Exception {
        if (log.isTraceEnabled()) {
            log.trace("Destroy initiated for " +
                    new InetSocketAddress(getAddress(),getPortWithOffset()));
        }
        if (running) {
            stop();
        }
        try {
            doCloseServerSocket();
        } catch (IOException ioe) {
            getLog().warn(sm.getString("endpoint.serverSocket.closeFailed", getName()), ioe);
        }
        destroySsl();
        super.unbind();
        if (getHandler() != null ) {
            getHandler().recycle();
        }
        if (log.isTraceEnabled()) {
            log.trace("Destroy completed for " +
                    new InetSocketAddress(getAddress(), getPortWithOffset()));
        }
    }


    @Override
    protected void doCloseServerSocket() throws IOException {
        if (!getUseInheritedChannel() && serverSock != null) {
            // Close server socket
            serverSock.close();
        }
        serverSock = null;
    }


    // ------------------------------------------------------ Protected Methods


    protected SynchronizedStack<NioChannel> getNioChannels() {
        return nioChannels;
    }


    protected Poller getPoller() {
        return poller;
    }


    protected CountDownLatch getStopLatch() {
        return stopLatch;
    }


    protected void setStopLatch(CountDownLatch stopLatch) {
        this.stopLatch = stopLatch;
    }


    /**
     * Process the specified connection.
     * @param socket The socket channel
     * @return <code>true</code> if the socket was correctly configured
     *  and processing may continue, <code>false</code> if the socket needs to be
     *  close immediately
     */
    @Override
    protected boolean setSocketOptions(SocketChannel socket) {
        NioSocketWrapper socketWrapper = null;
        try {
            // Allocate channel and wrapper
            NioChannel channel = null;
            /*
                 从对象池中获取 NioChannel对象,如果对象池都没有了,那么临时创建一个新的,当然首先需要创建一个 SocketBufferHandler对象
             */
            if (nioChannels != null) {
                channel = nioChannels.pop();
            }
            if (channel == null) {
                SocketBufferHandler bufhandler = new SocketBufferHandler(
                        socketProperties.getAppReadBufSize(), // default 8192B
                        socketProperties.getAppWriteBufSize(), //default 8192B
                        socketProperties.getDirectBuffer()); // 是否使用堆外内存
                if (isSSLEnabled()) { // Https连接,包含了SSL握手逻辑
                    channel = new SecureNioChannel(bufhandler, this);
                } else {
                    channel = new NioChannel(bufhandler); // 普通的Channel
                }
            }
            NioSocketWrapper newWrapper = new NioSocketWrapper(channel, this);
            channel.reset(socket, newWrapper); // 将 NioChannel 与新的 SocketChannel 和 NioSocketWrapper 绑定
            connections.put(socket, newWrapper); // 将连接注册到全局连接管理 Map(通过原生 Socket 快速查找对应的 Wrapper)
            socketWrapper = newWrapper;

            // Set socket properties
            // Disable blocking, polling will be used
            socket.configureBlocking(false); // 设置为非阻塞模式,这里针对的是socket「SocketChannel」
            // 将配置的 Socket 属性应用到底层 Socket
            socketProperties.setProperties(socket.socket());
            /*
                设置读写超时,但是需要注意的是：这与 socket.setSoTimeout() 不同
                soTimeout ：底层 Socket 阻塞读超时
                readTimeout/writeTimeout ：Tomcat 应用层超时，由 Poller 的 timeout() 方法检测

            */
            socketWrapper.setReadTimeout(getConnectionTimeout()); // Poller 检测读超时（客户端长时间不发数据）
            socketWrapper.setWriteTimeout(getConnectionTimeout()); // Poller 检测写超时（响应写入长时间阻塞）
            socketWrapper.setKeepAliveLeft(NioEndpoint.this.getMaxKeepAliveRequests()); // 设置 Keep-Alive 请求数 ， 设置该连接剩余可复用次数
            poller.register(socketWrapper);
            return true;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            try {
                log.error(sm.getString("endpoint.socketOptionsError"), t);
            } catch (Throwable tt) {
                ExceptionUtils.handleThrowable(tt);
            }
            if (socketWrapper == null) {
                destroySocket(socket);
            }
        }
        // Tell to close the socket if needed
        return false;
    }


    @Override
    protected void destroySocket(SocketChannel socket) {
        countDownConnection();
        try {
            socket.close();
        } catch (IOException ioe) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("endpoint.err.close"), ioe);
            }
        }
    }


    @Override
    protected NetworkChannel getServerSocket() {
        return serverSock;
    }


    @Override
    protected SocketChannel serverSocketAccept() throws Exception {
        // 调用accept()来接受新连接 - 阻塞方法(可以看到,对于Acceptor线程来说,并没有使用Selector)
        SocketChannel result = serverSock.accept();

        // Bug does not affect Windows. Skip the check on that platform.
        // linux bug? 暂时不关心
        if (!JrePlatform.IS_WINDOWS) {
            SocketAddress currentRemoteAddress = result.getRemoteAddress();
            long currentNanoTime = System.nanoTime();
            if (currentRemoteAddress.equals(previousAcceptedSocketRemoteAddress) &&
                    currentNanoTime - previousAcceptedSocketNanoTime < 1000) {
                throw new IOException(sm.getString("endpoint.err.duplicateAccept"));
            }
            previousAcceptedSocketRemoteAddress = currentRemoteAddress;
            previousAcceptedSocketNanoTime = currentNanoTime;
        }

        return result;
    }


    @Override
    protected Log getLog() {
        return log;
    }


    @Override
    protected Log getLogCertificate() {
        return logCertificate;
    }


    @Override
    protected SocketProcessorBase<NioChannel> createSocketProcessor(
            SocketWrapperBase<NioChannel> socketWrapper, SocketEvent event) {
        return new SocketProcessor(socketWrapper, event);
    }

    // ----------------------------------------------------- Poller Inner Classes

    /**
     * PollerEvent, cacheable object for poller events to avoid GC
     */
    public static class PollerEvent {

        private NioSocketWrapper socketWrapper;
        private int interestOps;

        public PollerEvent(NioSocketWrapper socketWrapper, int intOps) {
            reset(socketWrapper, intOps);
        }

        public void reset(NioSocketWrapper socketWrapper, int intOps) {
            this.socketWrapper = socketWrapper;
            interestOps = intOps;
        }

        public NioSocketWrapper getSocketWrapper() {
            return socketWrapper;
        }

        public int getInterestOps() {
            return interestOps;
        }

        public void reset() {
            reset(null, 0);
        }

        @Override
        public String toString() {
            return "Poller event: socket [" + socketWrapper.getSocket() + "], socketWrapper [" + socketWrapper +
                    "], interestOps [" + interestOps + "]";
        }
    }

    /**
     * Poller class.
     */
    /*
        Poller 是 Tomcat NIO 模型中的事件轮询器,负责监听已建立连接的 I/O 事件(可读/可写),是 Reactor 模式中的核心组件
            核心职责:
                - 监听 Socket I/O 事件: 使用 NIO Selector 监听多个 Socket 的读写事件
                - 事件分发: 当 Socket 就绪时,将其分发给工作线程池处理
                - 连接管理: 管理所有已建立的长连接(Keep-Alive)
                - 超时检测: 定期检查并清理超时的连接
    */
    public class Poller implements Runnable {

        private Selector selector; // NIO 多路复用选择器 - 用于关心IO事件 (OP_READ / OP_WRITE / OP_REGISTER)
        private final SynchronizedQueue<PollerEvent> events =
                new SynchronizedQueue<>(); // 事件队列(实现 GC-Free) - Acceptor线程会将事件对象(pollerEvent)放入到该队列中,然后Poller线程会进行消费

        private volatile boolean close = false; // 停机标识
        // Optimize expiration handling
        /*
            下次超时检查时间戳(性能优化)：?? 这个属性是什么意思？后面在看吧
            核心作用:
                - 减少超时检查频率：避免每次循环都遍历所有连接检查超时
                - 智能触发
                    - selector.select() 超时返回（说明负载低）
                    - 达到 nextExpiration 时间
                    - 服务器正在关闭
        */
        private long nextExpiration = 0;
        /*
            唤醒计数器（优化 selector 唤醒）
                - 减少不必要的 selector.wakeup() 调用（该操作成本高）
                - 无锁设计：使用 CAS 原子操作保证线程安全
            值:
                - 0: Poller正在处理事件,不需要唤醒
                >0: 已经有事件了,下一轮会直接调用selectNow()
                -1: Poller即将/正在select(),需要调用wakeup()唤醒
        */
        private AtomicLong wakeupCounter = new AtomicLong(0);

        private volatile int keyCount = 0; // 就绪的事件数量

        public Poller() throws IOException {
            this.selector = Selector.open();
        }

        public int getKeyCount() { return keyCount; }

        public Selector getSelector() { return selector; }

        /**
         * Destroy the poller.
         */
        protected void destroy() {
            // Wait for polltime before doing anything, so that the poller threads
            // exit, otherwise parallel closure of sockets which are still
            // in the poller can cause problems
            close = true;
            selector.wakeup();
        }

        private void addEvent(PollerEvent event) {
            events.offer(event); // 放入到 Poller中的events队列中
            // 这里是 递增并且返回递增后的值,这里递增后=0,那么说明之前等于-1(poller可能阻塞在select()上)
            if (wakeupCounter.incrementAndGet() == 0) { // 然后唤醒selector,因为Poller线程可能阻塞在select上
                selector.wakeup(); // 下面去看下 Poller的run()方法
            }
        }

        private PollerEvent createPollerEvent(NioSocketWrapper socketWrapper, int interestOps) {
            PollerEvent r = null;
            if (eventCache != null) {
                r = eventCache.pop();
            }
            if (r == null) {
                r = new PollerEvent(socketWrapper, interestOps);
            } else {
                r.reset(socketWrapper, interestOps);
            }
            return r;
        }

        /**
         * Add specified socket and associated pool to the poller. The socket will
         * be added to a temporary array, and polled first after a maximum amount
         * of time equal to pollTime (in most cases, latency will be much lower,
         * however).
         *
         * @param socketWrapper to add to the poller
         * @param interestOps Operations for which to register this socket with
         *                    the Poller
         */
        public void add(NioSocketWrapper socketWrapper, int interestOps) {
            PollerEvent pollerEvent = createPollerEvent(socketWrapper, interestOps);
            addEvent(pollerEvent);
            if (close) {
                processSocket(socketWrapper, SocketEvent.STOP, false);
            }
        }

        /**
         * Processes events in the event queue of the Poller.
         *
         * @return <code>true</code> if some events were processed,
         *   <code>false</code> if queue was empty
         */
        public boolean events() {
            boolean result = false;

            PollerEvent pe = null;
            /*
                处理队列中的任务(这个是由 Acceptor线程放入的)
            */
            for (int i = 0, size = events.size(); i < size && (pe = events.poll()) != null; i++ ) {
                result = true;
                NioSocketWrapper socketWrapper = pe.getSocketWrapper(); // 获取到 SocketWrapper
                SocketChannel sc = socketWrapper.getSocket().getIOChannel(); // 获取到 SocketChannel
                int interestOps = pe.getInterestOps(); // 获取到关心的事件 - 这里获取的是pe(也就是PollerEvent中的interestOps)中关心的事件,这里应该是OP_REGISTER
                if (sc == null) {
                    log.warn(sm.getString("endpoint.nio.nullSocketChannel"));
                    socketWrapper.close();
                } else if (interestOps == OP_REGISTER) { // 1. 新连接走这里的流程
                    try {
                        /*
                            socketChannel.register(selector,OP_READ,socketWrapper)
                            public final SelectionKey register(Selector sel, int ops, Object att)
                            在这里将当前客户端连接关注的事件设置为OP_READ,并且将socketWrapper作为附件
                            需要注意的是：这里的OP_REGISTER是Tomcat内部自己的事件标识，专门用来标识新连接
                            {而在Netty中则是通过attach来区分的，也即使用的是OP_READ}
                            ps:然后呢?读写事件谁来处理呢?先不看下面的else分支,而是返回到Poller#run()方法中
                        */
                        sc.register(getSelector(), SelectionKey.OP_READ, socketWrapper);
                    } catch (Exception x) {
                        log.error(sm.getString("endpoint.nio.registerFail"), x);
                    }
                } else { // 2.
                    final SelectionKey key = sc.keyFor(getSelector());
                    if (key == null) {
                        // The key was cancelled (e.g. due to socket closure)
                        // and removed from the selector while it was being
                        // processed. Count down the connections at this point
                        // since it won't have been counted down when the socket
                        // closed.
                        socketWrapper.close();
                    } else {
                        final NioSocketWrapper attachment = (NioSocketWrapper) key.attachment();
                        if (attachment != null) {
                            // We are registering the key to start with, reset the fairness counter.
                            try {
                                int ops = key.interestOps() | interestOps;
                                attachment.interestOps(ops);
                                key.interestOps(ops);
                            } catch (CancelledKeyException ckx) {
                                cancelledKey(key, socketWrapper);
                            }
                        } else {
                            cancelledKey(key, socketWrapper);
                        }
                    }
                }
                if (running && eventCache != null) {
                    pe.reset();
                    eventCache.push(pe);
                }
            }

            return result;
        }

        /**
         * Registers a newly created socket with the poller.
         *
         * @param socketWrapper The socket wrapper
         */
        public void register(final NioSocketWrapper socketWrapper) {
            // 设置客户端连接关心的事件 - OP_READ (socketWrapper中的interestOps = OP_READ)
            socketWrapper.interestOps(SelectionKey.OP_READ);//this is what OP_REGISTER turns into. OP_REGISTER 最终会转换成 OP_READ(这是什么意思?)
            /*
                 获取 PollerEvent对象,用于封装socket 和 其感兴趣的事情
                 PollerEvent{
                    private NioSocketWrapper socketWrapper; // 上面的socketWrapper
                    private int interestOps; // OP_REGISTER
                 }
            */
            PollerEvent pollerEvent = createPollerEvent(socketWrapper, OP_REGISTER);
            addEvent(pollerEvent);
        }

        public void cancelledKey(SelectionKey sk, SocketWrapperBase<NioChannel> socketWrapper) {
            if (JreCompat.isJre11Available() && socketWrapper != null) {
                socketWrapper.close();
            } else {
                try {
                    // If is important to cancel the key first, otherwise a deadlock may occur between the
                    // poller select and the socket channel close which would cancel the key
                    // This workaround is not needed on Java 11+
                    if (sk != null) {
                        sk.attach(null);
                        if (sk.isValid()) {
                            sk.cancel();
                        }
                    }
                } catch (Throwable e) {
                    ExceptionUtils.handleThrowable(e);
                    if (log.isDebugEnabled()) {
                        log.error(sm.getString("endpoint.debug.channelCloseFail"), e);
                    }
                } finally {
                    if (socketWrapper != null) {
                        socketWrapper.close();
                    }
                }
            }
        }

        /**
         * The background thread that adds sockets to the Poller, checks the
         * poller for triggered events and hands the associated socket off to an
         * appropriate processor as events occur.
         */
        @Override
        public void run() {
            // Loop until destroy() is called
            while (true) {

                boolean hasEvents = false;

                try {
                    if (!close) {
                        // 在events()中至少处理了一个事件(新连接 / 读 / 写)
                        hasEvents = events();
                        /*
                            wakeupCounter状态机：
                                - 0: 空闲
                                > 0: Acceptor()每次调用addEvent()都会调用incrementAndGet() - 这代表有事件了
                                -1: poller即将/已经阻塞在select()上
                        */
                        // 获取 wakeupCounter的值 并且设置为-1,如果大于0,说明有事件了,直接调用selectNow()返回就绪的事件个数
                        if (wakeupCounter.getAndSet(-1) > 0) {
                            // If we are here, means we have other stuff to do
                            // Do a non blocking select
                            keyCount = selector.selectNow();
                        } else { // 否则,wakeupCounter的旧值<=0，这代表没事件,那么阻塞在select上
                            keyCount = selector.select(selectorTimeout);
                        }
                        wakeupCounter.set(0); // 重置为0
                    }
                    // 关闭逻辑,暂时不考虑
                    if (close) {
                        events();
                        timeout(0, false);
                        try {
                            selector.close();
                        } catch (IOException ioe) {
                            log.error(sm.getString("endpoint.nio.selectorCloseFail"), ioe);
                        }
                        break;
                    }
                    // Either we timed out or we woke up, process events first
                    /*
                        上面的返回的keyCount = 0
                            - 可能是没有任何的socket有就绪的读写事件
                            - 可能是selectorTimeout超时(默认是1s)
                            - 或者被wakeup()唤醒但是实际上没有IO事件(比如新连接注册的时候)
                    */
                    if (keyCount == 0) {
                        // 更新hasEvents的值,因为在select()期间,Acceptor可能往events队列中添加了任务
                        hasEvents = (hasEvents | events());
                    }
                } catch (Throwable x) {
                    ExceptionUtils.handleThrowable(x);
                    log.error(sm.getString("endpoint.nio.selectorLoopError"), x);
                    continue;
                }
                /*
                    selectedKeys = {
                            SelectionKey1 (OP_READ 就绪, 附件=socketWrapper1),
                            SelectionKey2 (OP_WRITE 就绪, 附件=socketWrapper2),
                            ...
                        }
                     有就绪的事件则获取对应的迭代器,后续依次处理,我猜测后面只会处理Read/Write
                */
                Iterator<SelectionKey> iterator =
                    keyCount > 0 ? selector.selectedKeys().iterator() : null;
                // Walk through the collection of ready keys and dispatch
                // any active event.
                // 依次处理就绪的读写事件
                while (iterator != null && iterator.hasNext()) {
                    SelectionKey sk = iterator.next();
                    iterator.remove();
                    NioSocketWrapper socketWrapper = (NioSocketWrapper) sk.attachment(); // 获取到附件
                    // Attachment may be null if another thread has called
                    // cancelledKey()
                    if (socketWrapper != null) {
                        processKey(sk, socketWrapper); // 处理就绪的读写事件
                    }
                }

                // Process timeouts
                timeout(keyCount,hasEvents);
            }

            getStopLatch().countDown();
        }

        protected void processKey(SelectionKey sk, NioSocketWrapper socketWrapper) {
            try {
                if (close) {
                    cancelledKey(sk, socketWrapper);
                } else if (sk.isValid()) {
                    if (sk.isReadable() || sk.isWritable()) { // 对应的socket是否可读或者可写
                        if (socketWrapper.getSendfileData() != null) { // 文件读写,展示不考虑
                            processSendfile(sk, socketWrapper, false);
                        } else {
                            /*
                                这里是干什么？
                                从方法名上看,是取消注册,这对应的应该是register()方法,而register()的主要作用是注册到Selector上,并且关心对应的事件
                                而这里的unreg()方法则是做相反的操作，比如某个Socket关系OP_READ,那么在这里关心～OP_READ,也就是什么也都不关心
                                ===
                                为什么要这样做呢？比如当前的Socket中OP_READ事件就绪了,那么说明有数据可以读了,如果不取消掉会怎么样呢？
                                在下面最终会将读数据的操作提交给 工作线程池来处理,
                                如果不取消掉，此次读取数据的操作可能没有读取完数据「其实有没有读取完都没关系，因为只要有数据到了，那么Poller的下一次select()就会感知到」，
                                那么下次select()的时候针对该socket还会触发OP_READ事件,
                                这个时候Poller依旧是任务提交给线程池执行，这个时候不能保证读取数据的线程还是上一次的线程，
                                所以造成的后果是什么呢？两个线程同时在操作同一个socket(读取socket中的数据)
                                可能会有线程安全问题
                                所以在这里取消对应的事件关注,避免了线程安全问题
                                ===
                                那什么时候会重新注册呢？

                            */
                            unreg(sk, socketWrapper, sk.readyOps());
                            boolean closeSocket = false;
                            // Read goes before write
                            if (sk.isReadable()) { // 处理读事件
                                if (socketWrapper.readOperation != null) { // 1. 异步读事件
                                    if (!socketWrapper.readOperation.process()) {
                                        closeSocket = true;
                                    }
                                } else if (socketWrapper.readBlocking) { // 2.阻塞读等待
                                    synchronized (socketWrapper.readLock) {
                                        socketWrapper.readBlocking = false;
                                        socketWrapper.readLock.notify();
                                    }
                                } else if (!processSocket(socketWrapper, SocketEvent.OPEN_READ, true)) { // 3.常规处理 - 处理HTTP请求(processSocket())
                                    closeSocket = true;
                                }
                            }
                            if (!closeSocket && sk.isWritable()) { // 处理写事件
                                if (socketWrapper.writeOperation != null) {
                                    if (!socketWrapper.writeOperation.process()) {
                                        closeSocket = true;
                                    }
                                } else if (socketWrapper.writeBlocking) {
                                    synchronized (socketWrapper.writeLock) {
                                        socketWrapper.writeBlocking = false;
                                        socketWrapper.writeLock.notify();
                                    }
                                } else if (!processSocket(socketWrapper, SocketEvent.OPEN_WRITE, true)) {
                                    closeSocket = true;
                                }
                            }
                            if (closeSocket) {
                                cancelledKey(sk, socketWrapper);
                            }
                        }
                    }
                } else {
                    // Invalid key
                    cancelledKey(sk, socketWrapper);
                }
            } catch (CancelledKeyException ckx) {
                cancelledKey(sk, socketWrapper);
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.error(sm.getString("endpoint.nio.keyProcessingError"), t);
            }
        }

        public SendfileState processSendfile(SelectionKey sk, NioSocketWrapper socketWrapper,
                boolean calledByProcessor) {
            NioChannel sc = null;
            try {
                unreg(sk, socketWrapper, sk.readyOps());
                SendfileData sd = socketWrapper.getSendfileData();

                if (log.isTraceEnabled()) {
                    log.trace("Processing send file for: " + sd.fileName);
                }

                if (sd.fchannel == null) {
                    // Setup the file channel
                    File f = new File(sd.fileName);
                    @SuppressWarnings("resource") // Closed when channel is closed
                    FileInputStream fis = new FileInputStream(f);
                    sd.fchannel = fis.getChannel();
                }

                // Configure output channel
                sc = socketWrapper.getSocket();
                // TLS/SSL channel is slightly different
                WritableByteChannel wc = ((sc instanceof SecureNioChannel) ? sc : sc.getIOChannel());

                // We still have data in the buffer
                if (sc.getOutboundRemaining() > 0) {
                    if (sc.flushOutbound()) {
                        socketWrapper.updateLastWrite();
                    }
                } else {
                    long written = sd.fchannel.transferTo(sd.pos, sd.length, wc);
                    if (written > 0) {
                        sd.pos += written;
                        sd.length -= written;
                        socketWrapper.updateLastWrite();
                    } else {
                        // Unusual not to be able to transfer any bytes
                        // Check the length was set correctly
                        if (sd.fchannel.size() <= sd.pos) {
                            throw new IOException(sm.getString("endpoint.sendfile.tooMuchData"));
                        }
                    }
                }
                if (sd.length <= 0 && sc.getOutboundRemaining()<=0) {
                    if (log.isTraceEnabled()) {
                        log.trace("Send file complete for: " + sd.fileName);
                    }
                    socketWrapper.setSendfileData(null);
                    try {
                        sd.fchannel.close();
                    } catch (Exception ignore) {
                    }
                    // For calls from outside the Poller, the caller is
                    // responsible for registering the socket for the
                    // appropriate event(s) if sendfile completes.
                    if (!calledByProcessor) {
                        switch (sd.keepAliveState) {
                        case NONE: {
                            if (log.isTraceEnabled()) {
                                log.trace("Send file connection is being closed");
                            }
                            poller.cancelledKey(sk, socketWrapper);
                            break;
                        }
                        case PIPELINED: {
                            if (log.isTraceEnabled()) {
                                log.trace("Connection is keep alive, processing pipe-lined data");
                            }
                            if (!processSocket(socketWrapper, SocketEvent.OPEN_READ, true)) {
                                poller.cancelledKey(sk, socketWrapper);
                            }
                            break;
                        }
                        case OPEN: {
                            if (log.isTraceEnabled()) {
                                log.trace("Connection is keep alive, registering back for OP_READ");
                            }
                            reg(sk, socketWrapper, SelectionKey.OP_READ);
                            break;
                        }
                        }
                    }
                    return SendfileState.DONE;
                } else {
                    if (log.isTraceEnabled()) {
                        log.trace("OP_WRITE for sendfile: " + sd.fileName);
                    }
                    if (calledByProcessor) {
                        add(socketWrapper, SelectionKey.OP_WRITE);
                    } else {
                        reg(sk, socketWrapper, SelectionKey.OP_WRITE);
                    }
                    return SendfileState.PENDING;
                }
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("endpoint.sendfile.error"), e);
                }
                if (!calledByProcessor && sc != null) {
                    poller.cancelledKey(sk, socketWrapper);
                }
                return SendfileState.ERROR;
            } catch (Throwable t) {
                log.error(sm.getString("endpoint.sendfile.error"), t);
                if (!calledByProcessor && sc != null) {
                    poller.cancelledKey(sk, socketWrapper);
                }
                return SendfileState.ERROR;
            }
        }

        protected void unreg(SelectionKey sk, NioSocketWrapper socketWrapper, int readyOps) {
            // This is a must, so that we don't have multiple threads messing with the socket
            reg(sk, socketWrapper, sk.interestOps() & (~readyOps));
        }

        protected void reg(SelectionKey sk, NioSocketWrapper socketWrapper, int intops) {
            sk.interestOps(intops);
            socketWrapper.interestOps(intops);
        }

        protected void timeout(int keyCount, boolean hasEvents) {
            long now = System.currentTimeMillis();
            // This method is called on every loop of the Poller. Don't process
            // timeouts on every loop of the Poller since that would create too
            // much load and timeouts can afford to wait a few seconds.
            // However, do process timeouts if any of the following are true:
            // - the selector simply timed out (suggests there isn't much load)
            // - the nextExpiration time has passed
            // - the server socket is being closed
            if (nextExpiration > 0 && (keyCount > 0 || hasEvents) && (now < nextExpiration) && !close) {
                return;
            }
            int keycount = 0;
            try {
                for (SelectionKey key : selector.keys()) {
                    keycount++;
                    NioSocketWrapper socketWrapper = (NioSocketWrapper) key.attachment();
                    try {
                        if (socketWrapper == null) {
                            // We don't support any keys without attachments
                            cancelledKey(key, null);
                        } else if (close) {
                            key.interestOps(0);
                            // Avoid duplicate stop calls
                            socketWrapper.interestOps(0);
                            cancelledKey(key, socketWrapper);
                        } else if (socketWrapper.interestOpsHas(SelectionKey.OP_READ) ||
                                  socketWrapper.interestOpsHas(SelectionKey.OP_WRITE)) {
                            boolean readTimeout = false;
                            boolean writeTimeout = false;
                            // Check for read timeout
                            if (socketWrapper.interestOpsHas(SelectionKey.OP_READ)) {
                                long delta = now - socketWrapper.getLastRead();
                                long timeout = socketWrapper.getReadTimeout();
                                if (timeout > 0 && delta > timeout) {
                                    readTimeout = true;
                                }
                            }
                            // Check for write timeout
                            if (!readTimeout && socketWrapper.interestOpsHas(SelectionKey.OP_WRITE)) {
                                long delta = now - socketWrapper.getLastWrite();
                                long timeout = socketWrapper.getWriteTimeout();
                                if (timeout > 0 && delta > timeout) {
                                    writeTimeout = true;
                                }
                            }
                            if (readTimeout || writeTimeout) {
                                key.interestOps(0);
                                // Avoid duplicate timeout calls
                                socketWrapper.interestOps(0);
                                socketWrapper.setError(new SocketTimeoutException());
                                if (readTimeout && socketWrapper.readOperation != null) {
                                    if (!socketWrapper.readOperation.process()) {
                                        cancelledKey(key, socketWrapper);
                                    }
                                } else if (writeTimeout && socketWrapper.writeOperation != null) {
                                    if (!socketWrapper.writeOperation.process()) {
                                        cancelledKey(key, socketWrapper);
                                    }
                                } else if (!processSocket(socketWrapper, SocketEvent.ERROR, true)) {
                                    cancelledKey(key, socketWrapper);
                                }
                            }
                        }
                    } catch (CancelledKeyException ckx) {
                        cancelledKey(key, socketWrapper);
                    }
                }
            } catch (ConcurrentModificationException cme) {
                // See https://bz.apache.org/bugzilla/show_bug.cgi?id=57943
                log.warn(sm.getString("endpoint.nio.timeoutCme"), cme);
            }
            // For logging purposes only
            long prevExp = nextExpiration;
            nextExpiration = System.currentTimeMillis() +
                    socketProperties.getTimeoutInterval();
            if (log.isTraceEnabled()) {
                log.trace("timeout completed: keys processed=" + keycount +
                        "; now=" + now + "; nextExpiration=" + prevExp +
                        "; keyCount=" + keyCount + "; hasEvents=" + hasEvents +
                        "; eval=" + ((now < prevExp) && (keyCount>0 || hasEvents) && (!close) ));
            }

        }
    }

    // --------------------------------------------------- Socket Wrapper Class
    // 该类是Tomcat对单个客户端连接的完整封装
    public static class NioSocketWrapper extends SocketWrapperBase<NioChannel> {

        private final SynchronizedStack<NioChannel> nioChannels;
        private final Poller poller;

        private int interestOps = 0; // 关注的事件
        private volatile SendfileData sendfileData = null;
        private volatile long lastRead = System.currentTimeMillis();
        private volatile long lastWrite = lastRead;

        private final Object readLock;
        private volatile boolean readBlocking = false;
        private final Object writeLock;
        private volatile boolean writeBlocking = false;

        public NioSocketWrapper(NioChannel channel, NioEndpoint endpoint) {
            super(channel, endpoint); // 保存 NioChannel 和 endpoint引用
            nioChannels = endpoint.getNioChannels(); // 保存对象池引用，连接关闭时用于回收 NioChannel
            poller = endpoint.getPoller(); // 保存 Poller 引用，后续注册/取消事件时使用
            socketBufferHandler = channel.getBufHandler(); // 获取 NioChannel 的读写缓冲区处理器
            readLock = (readPending == null) ? new Object() : readPending; // 用于阻塞式读写的线程同步
            writeLock = (writePending == null) ? new Object() : writePending;
        }

        public Poller getPoller() { return poller; }
        public int interestOps() { return interestOps; }
        public int interestOps(int ops) { this.interestOps  = ops; return ops; }
        public boolean interestOpsHas(int targetOp) {
            return (this.interestOps() & targetOp) == targetOp;
        }

        public void setSendfileData(SendfileData sf) { this.sendfileData = sf;}
        public SendfileData getSendfileData() { return this.sendfileData; }

        public void updateLastWrite() { lastWrite = System.currentTimeMillis(); }
        public long getLastWrite() { return lastWrite; }
        public void updateLastRead() { lastRead = System.currentTimeMillis(); }
        public long getLastRead() { return lastRead; }

        @Override
        public boolean isReadyForRead() throws IOException {
            socketBufferHandler.configureReadBufferForRead();

            if (socketBufferHandler.getReadBuffer().remaining() > 0) {
                return true;
            }

            fillReadBuffer(false);

            boolean isReady = socketBufferHandler.getReadBuffer().position() > 0;
            return isReady;
        }


        @Override
        public int read(boolean block, byte[] b, int off, int len) throws IOException {
            int nRead = populateReadBuffer(b, off, len);
            if (nRead > 0) {
                return nRead;
                /*
                 * Since more bytes may have arrived since the buffer was last
                 * filled, it is an option at this point to perform a
                 * non-blocking read. However correctly handling the case if
                 * that read returns end of stream adds complexity. Therefore,
                 * at the moment, the preference is for simplicity.
                 */
            }

            // Fill the read buffer as best we can.
            nRead = fillReadBuffer(block);
            updateLastRead();

            // Fill as much of the remaining byte array as possible with the
            // data that was just read
            if (nRead > 0) {
                socketBufferHandler.configureReadBufferForRead();
                nRead = Math.min(nRead, len);
                socketBufferHandler.getReadBuffer().get(b, off, nRead);
            }
            return nRead;
        }


        @Override
        public int read(boolean block, ByteBuffer to) throws IOException {
            int nRead = populateReadBuffer(to);
            if (nRead > 0) {
                return nRead;
                /*
                 * Since more bytes may have arrived since the buffer was last
                 * filled, it is an option at this point to perform a
                 * non-blocking read. However correctly handling the case if
                 * that read returns end of stream adds complexity. Therefore,
                 * at the moment, the preference is for simplicity.
                 */
            }

            // The socket read buffer capacity is socket.appReadBufSize
            int limit = socketBufferHandler.getReadBuffer().capacity();
            if (to.remaining() >= limit) {
                to.limit(to.position() + limit);
                nRead = fillReadBuffer(block, to);
                if (log.isTraceEnabled()) {
                    log.trace("Socket: [" + this + "], Read direct from socket: [" + nRead + "]");
                }
                updateLastRead();
            } else {
                // Fill the read buffer as best we can.
                nRead = fillReadBuffer(block);
                if (log.isTraceEnabled()) {
                    log.trace("Socket: [" + this + "], Read into buffer: [" + nRead + "]");
                }
                updateLastRead();

                // Fill as much of the remaining byte array as possible with the
                // data that was just read
                if (nRead > 0) {
                    nRead = populateReadBuffer(to);
                }
            }
            return nRead;
        }


        @Override
        protected void doClose() {
            if (log.isTraceEnabled()) {
                log.trace("Calling [" + getEndpoint() + "].closeSocket([" + this + "])");
            }
            try {
                getEndpoint().connections.remove(getSocket().getIOChannel());
                if (getSocket().isOpen()) {
                    getSocket().close(true);
                }
                if (getEndpoint().running) {
                    if (nioChannels == null || !nioChannels.push(getSocket())) {
                        getSocket().free();
                    }
                }
            } catch (Throwable e) {
                ExceptionUtils.handleThrowable(e);
                if (log.isDebugEnabled()) {
                    log.error(sm.getString("endpoint.debug.channelCloseFail"), e);
                }
            } finally {
                socketBufferHandler = SocketBufferHandler.EMPTY;
                nonBlockingWriteBuffer.clear();
                reset(NioChannel.CLOSED_NIO_CHANNEL);
            }
            try {
                SendfileData data = getSendfileData();
                if (data != null && data.fchannel != null && data.fchannel.isOpen()) {
                    data.fchannel.close();
                }
            } catch (Throwable e) {
                ExceptionUtils.handleThrowable(e);
                if (log.isDebugEnabled()) {
                    log.error(sm.getString("endpoint.sendfile.closeError"), e);
                }
            }
        }

        private int fillReadBuffer(boolean block) throws IOException {
            socketBufferHandler.configureReadBufferForWrite();
            return fillReadBuffer(block, socketBufferHandler.getReadBuffer());
        }


        private int fillReadBuffer(boolean block, ByteBuffer buffer) throws IOException {
            int n = 0;
            if (getSocket() == NioChannel.CLOSED_NIO_CHANNEL) {
                throw new ClosedChannelException();
            }
            if (block) {
                long timeout = getReadTimeout();
                long startNanos = 0;
                do {
                    if (startNanos > 0) {
                        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
                        if (elapsedMillis == 0) {
                            elapsedMillis = 1;
                        }
                        timeout -= elapsedMillis;
                        if (timeout <= 0) {
                            throw new SocketTimeoutException();
                        }
                    }
                    synchronized (readLock) {
                        n = getSocket().read(buffer);
                        if (n == -1) {
                            throw new EOFException();
                        } else if (n == 0) {
                            // Ensure a spurious wake-up doesn't trigger a duplicate registration
                            if (!readBlocking) {
                                readBlocking = true;
                                registerReadInterest();
                            }
                            try {
                                if (timeout > 0) {
                                    startNanos = System.nanoTime();
                                    readLock.wait(timeout);
                                } else {
                                    readLock.wait();
                                }
                            } catch (InterruptedException e) {
                                // Continue
                            }
                        }
                    }
                } while (n == 0); // TLS needs to loop as reading zero application bytes is possible
            } else {
                n = getSocket().read(buffer);
                if (n == -1) {
                    throw new EOFException();
                }
            }
            return n;
        }


        @Override
        protected boolean flushNonBlocking() throws IOException {
            boolean dataLeft = socketOrNetworkBufferHasDataLeft();

            // Write to the socket, if there is anything to write
            if (dataLeft) {
                doWrite(false);
                dataLeft = socketOrNetworkBufferHasDataLeft();
            }

            if (!dataLeft && !nonBlockingWriteBuffer.isEmpty()) {
                dataLeft = nonBlockingWriteBuffer.write(this, false);

                if (!dataLeft && socketOrNetworkBufferHasDataLeft()) {
                    doWrite(false);
                    dataLeft = socketOrNetworkBufferHasDataLeft();
                }
            }

            return dataLeft;
        }


        /*
         * https://bz.apache.org/bugzilla/show_bug.cgi?id=66076
         *
         * When using TLS an additional buffer is used for the encrypted data
         * before it is written to the network. It is possible for this network
         * output buffer to contain data while the socket write buffer is empty.
         *
         * For NIO with non-blocking I/O, this case is handling by ensuring that
         * flush only returns false (i.e. no data left to flush) if all buffers
         * are empty.
         */
        private boolean socketOrNetworkBufferHasDataLeft() {
            return !socketBufferHandler.isWriteBufferEmpty() || getSocket().getOutboundRemaining() > 0;
        }


        @Override
        protected void doWrite(boolean block, ByteBuffer buffer) throws IOException {
            int n = 0;
            if (getSocket() == NioChannel.CLOSED_NIO_CHANNEL) {
                throw new ClosedChannelException();
            }
            if (block) {
                if (previousIOException != null) {
                    /*
                     * Socket has previously timed out.
                     *
                     * Blocking writes assume that buffer is always fully
                     * written so there is no code checking for incomplete
                     * writes, retaining the unwritten data and attempting to
                     * write it as part of a subsequent write call.
                     *
                     * Because of the above, when a timeout is triggered we need
                     * to skip subsequent attempts to write as otherwise it will
                     * appear to the client as if some data was dropped just
                     * before the connection is lost. It is better if the client
                     * just sees the dropped connection.
                     */
                    throw new IOException(previousIOException);
                }
                long timeout = getWriteTimeout();
                long startNanos = 0;
                do {
                    if (startNanos > 0) {
                        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
                        if (elapsedMillis == 0) {
                            elapsedMillis = 1;
                        }
                        timeout -= elapsedMillis;
                        if (timeout <= 0) {
                            previousIOException = new SocketTimeoutException();
                            throw previousIOException;
                        }
                    }
                    synchronized (writeLock) {
                        n = getSocket().write(buffer);
                        // n == 0 could be an incomplete write but it could also
                        // indicate that a previous incomplete write of the
                        // outbound buffer (for TLS) has now completed. Only
                        // block if there is still data to write.
                        if (n == 0 && (buffer.hasRemaining() || getSocket().getOutboundRemaining() > 0)) {
                            // Ensure a spurious wake-up doesn't trigger a duplicate registration
                            if (!writeBlocking) {
                                writeBlocking = true;
                                registerWriteInterest();
                            }
                            try {
                                if (timeout > 0) {
                                    startNanos = System.nanoTime();
                                    writeLock.wait(timeout);
                                } else {
                                    writeLock.wait();
                                }
                            } catch (InterruptedException e) {
                                // Continue
                            }
                        } else if (startNanos > 0) {
                            // If something was written, reset timeout
                            timeout = getWriteTimeout();
                            startNanos = 0;
                        }
                    }
                } while (buffer.hasRemaining() || getSocket().getOutboundRemaining() > 0);
            } else {
                do {
                    n = getSocket().write(buffer);
                } while (n > 0 && buffer.hasRemaining());
                // If there is data left in the buffer the socket will be registered for
                // write further up the stack. This is to ensure the socket is only
                // registered for write once as both container and user code can trigger
                // write registration.
            }
            updateLastWrite();
        }


        @Override
        public void registerReadInterest() {
            if (log.isTraceEnabled()) {
                log.trace(sm.getString("endpoint.debug.registerRead", this));
            }
            getPoller().add(this, SelectionKey.OP_READ);
        }


        @Override
        public void registerWriteInterest() {
            if (log.isTraceEnabled()) {
                log.trace(sm.getString("endpoint.debug.registerWrite", this));
            }
            getPoller().add(this, SelectionKey.OP_WRITE);
        }


        @Override
        public SendfileDataBase createSendfileData(String filename, long pos, long length) {
            return new SendfileData(filename, pos, length);
        }


        @Override
        public SendfileState processSendfile(SendfileDataBase sendfileData) {
            setSendfileData((SendfileData) sendfileData);
            SelectionKey key = getSocket().getIOChannel().keyFor(getPoller().getSelector());
            if (key == null) {
                return SendfileState.ERROR;
            } else {
                // Might as well do the first write on this thread
                return getPoller().processSendfile(key, this, true);
            }
        }


        @Override
        protected void populateRemoteAddr() {
            SocketChannel sc = getSocket().getIOChannel();
            if (sc != null) {
                InetAddress inetAddr = sc.socket().getInetAddress();
                if (inetAddr != null) {
                    remoteAddr = inetAddr.getHostAddress();
                }
            }
        }


        @Override
        protected void populateRemoteHost() {
            SocketChannel sc = getSocket().getIOChannel();
            if (sc != null) {
                InetAddress inetAddr = sc.socket().getInetAddress();
                if (inetAddr != null) {
                    remoteHost = inetAddr.getHostName();
                    if (remoteAddr == null) {
                        remoteAddr = inetAddr.getHostAddress();
                    }
                }
            }
        }


        @Override
        protected void populateRemotePort() {
            SocketChannel sc = getSocket().getIOChannel();
            if (sc != null) {
                remotePort = sc.socket().getPort();
            }
        }


        @Override
        protected void populateLocalName() {
            SocketChannel sc = getSocket().getIOChannel();
            if (sc != null) {
                InetAddress inetAddr = sc.socket().getLocalAddress();
                if (inetAddr != null) {
                    localName = inetAddr.getHostName();
                }
            }
        }


        @Override
        protected void populateLocalAddr() {
            SocketChannel sc = getSocket().getIOChannel();
            if (sc != null) {
                InetAddress inetAddr = sc.socket().getLocalAddress();
                if (inetAddr != null) {
                    localAddr = inetAddr.getHostAddress();
                }
            }
        }


        @Override
        protected void populateLocalPort() {
            SocketChannel sc = getSocket().getIOChannel();
            if (sc != null) {
                localPort = sc.socket().getLocalPort();
            }
        }


        /**
         * {@inheritDoc}
         * @param clientCertProvider Ignored for this implementation
         */
        @Override
        public SSLSupport getSslSupport(String clientCertProvider) {
            if (getSocket() instanceof SecureNioChannel) {
                SecureNioChannel ch = (SecureNioChannel) getSocket();
                return ch.getSSLSupport();
            }
            return null;
        }


        @Override
        public void doClientAuth(SSLSupport sslSupport) throws IOException {
            SecureNioChannel sslChannel = (SecureNioChannel) getSocket();
            SSLEngine engine = sslChannel.getSslEngine();
            if (!engine.getNeedClientAuth()) {
                // Need to re-negotiate SSL connection
                engine.setNeedClientAuth(true);
                sslChannel.rehandshake(getEndpoint().getConnectionTimeout());
                ((JSSESupport) sslSupport).setSession(engine.getSession());
            }
        }


        @Override
        public void setAppReadBufHandler(ApplicationBufferHandler handler) {
            getSocket().setAppReadBufHandler(handler);
        }

        @Override
        protected <A> OperationState<A> newOperationState(boolean read,
                ByteBuffer[] buffers, int offset, int length,
                BlockingMode block, long timeout, TimeUnit unit, A attachment,
                CompletionCheck check, CompletionHandler<Long, ? super A> handler,
                Semaphore semaphore, VectoredIOCompletionHandler<A> completion) {
            return new NioOperationState<>(read, buffers, offset, length, block,
                    timeout, unit, attachment, check, handler, semaphore, completion);
        }

        private class NioOperationState<A> extends OperationState<A> {
            private volatile boolean inline = true;
            private NioOperationState(boolean read, ByteBuffer[] buffers, int offset, int length,
                    BlockingMode block, long timeout, TimeUnit unit, A attachment, CompletionCheck check,
                    CompletionHandler<Long, ? super A> handler, Semaphore semaphore,
                    VectoredIOCompletionHandler<A> completion) {
                super(read, buffers, offset, length, block,
                        timeout, unit, attachment, check, handler, semaphore, completion);
            }

            @Override
            protected boolean isInline() {
                return inline;
            }

            @Override
            protected boolean hasOutboundRemaining() {
                return getSocket().getOutboundRemaining() > 0;
            }

            @Override
            public void run() {
                // Perform the IO operation
                // Called from the poller to continue the IO operation
                long nBytes = 0;
                if (getError() == null) {
                    try {
                        synchronized (this) {
                            if (!completionDone) {
                                // This filters out same notification until processing
                                // of the current one is done
                                if (log.isTraceEnabled()) {
                                    log.trace("Skip concurrent " + (read ? "read" : "write") + " notification");
                                }
                                return;
                            }
                            if (read) {
                                // Read from main buffer first
                                if (!socketBufferHandler.isReadBufferEmpty()) {
                                    // There is still data inside the main read buffer, it needs to be read first
                                    socketBufferHandler.configureReadBufferForRead();
                                    for (int i = 0; i < length && !socketBufferHandler.isReadBufferEmpty(); i++) {
                                        nBytes += transfer(socketBufferHandler.getReadBuffer(), buffers[offset + i]);
                                    }
                                }
                                if (nBytes == 0) {
                                    nBytes = getSocket().read(buffers, offset, length);
                                    updateLastRead();
                                }
                            } else {
                                boolean doWrite = true;
                                // Write from main buffer first
                                if (socketOrNetworkBufferHasDataLeft()) {
                                    // There is still data inside the main write buffer, it needs to be written first
                                    socketBufferHandler.configureWriteBufferForRead();
                                    do {
                                        nBytes = getSocket().write(socketBufferHandler.getWriteBuffer());
                                    } while (socketOrNetworkBufferHasDataLeft() && nBytes > 0);
                                    if (socketOrNetworkBufferHasDataLeft()) {
                                        doWrite = false;
                                    }
                                    // Preserve a negative value since it is an error
                                    if (nBytes > 0) {
                                        nBytes = 0;
                                    }
                                }
                                if (doWrite) {
                                    long n = 0;
                                    do {
                                        n = getSocket().write(buffers, offset, length);
                                        if (n == -1) {
                                            nBytes = n;
                                        } else {
                                            nBytes += n;
                                        }
                                    } while (n > 0);
                                    updateLastWrite();
                                }
                            }
                            if (nBytes != 0 || (!buffersArrayHasRemaining(buffers, offset, length) &&
                                    !socketOrNetworkBufferHasDataLeft())) {
                                completionDone = false;
                            }
                        }
                    } catch (IOException e) {
                        setError(e);
                    }
                }
                if (nBytes > 0 || (nBytes == 0 && !buffersArrayHasRemaining(buffers, offset, length) &&
                        !socketOrNetworkBufferHasDataLeft())) {
                    // The bytes processed are only updated in the completion handler
                    completion.completed(Long.valueOf(nBytes), this);
                } else if (nBytes < 0 || getError() != null) {
                    IOException error = getError();
                    if (error == null) {
                        error = new EOFException();
                    }
                    completion.failed(error, this);
                } else {
                    // As soon as the operation uses the poller, it is no longer inline
                    inline = false;
                    if (read) {
                        registerReadInterest();
                    } else {
                        registerWriteInterest();
                    }
                }
            }
        }
    }


    // ---------------------------------------------- SocketProcessor Inner Class

    /**
     * This class is the equivalent of the Worker, but will simply use in an
     * external Executor thread pool.
     */
    protected class SocketProcessor extends SocketProcessorBase<NioChannel> {

        public SocketProcessor(SocketWrapperBase<NioChannel> socketWrapper, SocketEvent event) {
            super(socketWrapper, event);
        }

        @Override
        protected void doRun() {
            /*
             * Do not cache and re-use the value of socketWrapper.getSocket() in
             * this method. If the socket closes the value will be updated to
             * CLOSED_NIO_CHANNEL and the previous value potentially re-used for
             * a new connection. That can result in a stale cached value which
             * in turn can result in unintentionally closing currently active
             * connections.
             */
            Poller poller = NioEndpoint.this.poller; // 获取到对应的poller对象
            if (poller == null) {
                socketWrapper.close();
                return;
            }

            try {
                int handshake = -1;
                try {
                    // === 1. SSL/TLS 握手处理,对于HTTP来说不需要处理
                    if (socketWrapper.getSocket().isHandshakeComplete()) {
                        // No TLS handshaking required. Let the handler
                        // process this socket / event combination.
                        handshake = 0; // 握手完成或者不需要握手,对于HTTP请求走这个分支, handshake=0
                    } else if (event == SocketEvent.STOP || event == SocketEvent.DISCONNECT ||
                            event == SocketEvent.ERROR) {
                        // Unable to complete the TLS handshake. Treat it as
                        // if the handshake failed.
                        handshake = -1; // 错误/停止事件
                    } else {
                        handshake = socketWrapper.getSocket().handshake(event == SocketEvent.OPEN_READ, event == SocketEvent.OPEN_WRITE);
                        // The handshake process reads/writes from/to the
                        // socket. status may therefore be OPEN_WRITE once
                        // the handshake completes. However, the handshake
                        // happens when the socket is opened so the status
                        // must always be OPEN_READ after it completes. It
                        // is OK to always set this as it is only used if
                        // the handshake completes.
                        event = SocketEvent.OPEN_READ;
                    }
                } catch (IOException x) {
                    handshake = -1;
                    if (logHandshake.isDebugEnabled()) {
                        logHandshake.debug(sm.getString("endpoint.err.handshake",
                                socketWrapper.getRemoteAddr(), Integer.toString(socketWrapper.getRemotePort())), x);
                    }
                } catch (CancelledKeyException ckx) {
                    handshake = -1;
                }
                // http请求走这个分支
                if (handshake == 0) {
                    SocketState state = SocketState.OPEN; // 默认状态:连接保持打开
                    // Process the request from this socket
                    if (event == null) { // 如果传入的event为空,默认当作读事件
                        state = getHandler().process(socketWrapper, SocketEvent.OPEN_READ);
                    } else { // 否则使用传入的事件类型(在这里是关注的是读事件)
                        // 核心逻辑：获取Handle
                        state = getHandler().process(socketWrapper, event);
                    }
                    if (state == SocketState.CLOSED) {
                        poller.cancelledKey(getSelectionKey(), socketWrapper);
                    }
                } else if (handshake == -1 ) {
                    getHandler().process(socketWrapper, SocketEvent.CONNECT_FAIL);
                    poller.cancelledKey(getSelectionKey(), socketWrapper);
                } else if (handshake == SelectionKey.OP_READ){
                    socketWrapper.registerReadInterest();
                } else if (handshake == SelectionKey.OP_WRITE){
                    socketWrapper.registerWriteInterest();
                }
            } catch (CancelledKeyException cx) {
                poller.cancelledKey(getSelectionKey(), socketWrapper);
            } catch (VirtualMachineError vme) {
                ExceptionUtils.handleThrowable(vme);
            } catch (Throwable t) {
                log.error(sm.getString("endpoint.processing.fail"), t);
                poller.cancelledKey(getSelectionKey(), socketWrapper);
            } finally {
                socketWrapper = null;
                event = null;
                //return to cache
                if (running && processorCache != null) {
                    processorCache.push(this);
                }
            }
        }

        private SelectionKey getSelectionKey() {
            // Shortcut for Java 11 onwards
            if (JreCompat.isJre11Available()) {
                return null;
            }

            SocketChannel socketChannel = socketWrapper.getSocket().getIOChannel();
            if (socketChannel == null) {
                return null;
            }

            return socketChannel.keyFor(NioEndpoint.this.poller.getSelector());
        }
    }


    // ----------------------------------------------- SendfileData Inner Class

    /**
     * SendfileData class.
     */
    public static class SendfileData extends SendfileDataBase {

        public SendfileData(String filename, long pos, long length) {
            super(filename, pos, length);
        }

        protected volatile FileChannel fchannel;
    }
}
