/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.threads;

import java.util.Collection;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.tomcat.util.res.StringManager;

/**
 * As task queue specifically designed to run with a thread pool executor. The
 * task queue is optimised to properly utilize threads within a thread pool
 * executor. If you use a normal queue, the executor will spawn threads when
 * there are idle threads and you won't be able to force items onto the queue
 * itself.
 */
public class TaskQueue extends LinkedBlockingQueue<Runnable> {

    private static final long serialVersionUID = 1L;
    protected static final StringManager sm = StringManager.getManager(TaskQueue.class);

    private transient volatile ThreadPoolExecutor parent = null;

    public TaskQueue() {
        super();
    }

    public TaskQueue(int capacity) {
        super(capacity);
    }

    public TaskQueue(Collection<? extends Runnable> c) {
        super(c);
    }

    public void setParent(ThreadPoolExecutor tp) {
        parent = tp;
    }


    /**
     * Used to add a task to the queue if the task has been rejected by the Executor.
     *
     * @param o         The task to add to the queue
     *
     * @return          {@code true} if the task was added to the queue,
     *                      otherwise {@code false}
     */
    public boolean force(Runnable o) {
        if (parent == null || parent.isShutdown()) {
            throw new RejectedExecutionException(sm.getString("taskQueue.notRunning"));
        }
        return super.offer(o); //forces the item onto the queue, to be used if the task is rejected
    }


    /**
     * Used to add a task to the queue if the task has been rejected by the Executor.
     *
     * @param o         The task to add to the queue
     * @param timeout   The timeout to use when adding the task
     * @param unit      The units in which the timeout is expressed
     *
     * @return          {@code true} if the task was added to the queue,
     *                      otherwise {@code false}
     *
     * @throws InterruptedException If the call is interrupted before the
     *                              timeout expires
     *
     * @deprecated Unused. Will be removed in Tomcat 10.1.x.
     */
    @Deprecated
    public boolean force(Runnable o, long timeout, TimeUnit unit) throws InterruptedException {
        if (parent == null || parent.isShutdown()) {
            throw new RejectedExecutionException(sm.getString("taskQueue.notRunning"));
        }
        return super.offer(o,timeout,unit); //forces the item onto the queue, to be used if the task is rejected
    }


    @Override
    public boolean offer(Runnable o) {
      //we can't do any checks
        if (parent==null) {
            return super.offer(o);
        }
        //we are maxed out on threads, simply queue the object
        /*
            getPoolSizeNoLock -> workers : 也就是线程池的工作线程数
            getSubmittedCount -> 表示已提交但是尚未完成的任务总数，包含3部分，这里需要知道的是：一个线程某一时刻只能拿一个任务
                - 队列中等待的任务 - 在workQueue中排队的任务
                - 已经分配给工作线程但是还未开始执行的任务(线程拿到了任务，但是还没有run)
                - 正在执行中的任务
        */
        // 1. 线程数已经到达了最大值,必须排队了,调用super.offer()
        if (parent.getPoolSizeNoLock() == parent.getMaximumPoolSize()) {
            return super.offer(o);
        }
        //we have idle threads, just add it to the queue
        /*
            2. 已提交但是未完成的任务数 <= 当前线程池中的工作线程数
               这就代表了此时有空闲线程(不准确，因为这里使用的是<=,而不是<)，这里以工作线程数 = 10为例(与核心线程数相等)
               需要注意的是：当调用execute()的时候就会执行：submittedCount.incrementAndGet();
               如果是第11个任务,那么被提交的那一刻： submittedCount = 11(假设前面10个任务还没有被执行完毕)
               getSubmittedCount <= 10 : 此时队列中没有任务，并且有空闲的线程(因为一个线程只能拿一个任务,这里还有其他线程没有获取到任务)
               getSubmittedCount(比如第11个任务) > 10 : 此时不会入队,进入到第3个分支

        */
        if (parent.getSubmittedCount() <= parent.getPoolSizeNoLock()) {
            return super.offer(o);
        }
        //if we have less threads than maximum force creation of a new thread
        /*
            3. 工作线程数 < 最大线程数
               返回false,注意这里是线程池进入到的offer()，这里返回false后,相当于入队列失败了，那么就会创建一个新的线程来执行任务
        */
        if (parent.getPoolSizeNoLock() < parent.getMaximumPoolSize()) {
            return false;
        }
        //if we reached here, we need to add it to the queue
        // 走到这里是说明到达最大线程数了，那么必须进入到队列中等待了
        return super.offer(o);
    }


    @Override
    public Runnable poll(long timeout, TimeUnit unit)
            throws InterruptedException {
        Runnable runnable = super.poll(timeout, unit);
        if (runnable == null && parent != null) {
            // the poll timed out, it gives an opportunity to stop the current
            // thread if needed to avoid memory leaks.
            parent.stopCurrentThreadIfNeeded();
        }
        return runnable;
    }

    @Override
    public Runnable take() throws InterruptedException {
        if (parent != null && parent.currentThreadShouldBeStopped()) {
            return poll(parent.getKeepAliveTime(TimeUnit.MILLISECONDS),
                    TimeUnit.MILLISECONDS);
            // yes, this may return null (in case of timeout) which normally
            // does not occur with take()
            // but the ThreadPoolExecutor implementation allows this
        }
        return super.take();
    }

}
