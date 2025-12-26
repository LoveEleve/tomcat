/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.collections;

/**
 * This is intended as a (mostly) GC-free alternative to
 * {@link java.util.concurrent.ConcurrentLinkedQueue} when the requirement is to
 * create an unbounded queue with no requirement to shrink the queue. The aim is
 * to provide the bare minimum of required functionality as quickly as possible
 * with minimum garbage.
 *
 * @param <T> The type of object managed by this queue
 */
/*
    都说 Netty 性能高，我 Tomcat 剑也未尝不利
    自定义实现的队列,实现 GC-Free,和 Disruptor有一样的设计，那就是循环队列 + 固定元素(元素不会被销毁，无GC压力)
    相比于 JDK中的队列，需要频繁的创建和销毁Node节点

    ===> 可惜,阅读完代码后发现和Disruptor是不一样的设计，Disruptor才是真的 GC-FREE
    在这里还是会创建 PollerEvent对象,只不过没有使用Node来包装而已(JDK的做法)
    ===>
    不对,这里和Disruptor是一样的，因为PollerEvent有对象池啊 - 所以依旧：我剑也未尝不利
*/
public class SynchronizedQueue<T> {

    public static final int DEFAULT_SIZE = 128; // 默认数组大小

    private Object[] queue; // 循环数组
    private int size; // 128
    private int insert = 0; // 下一次插入元素的位置 - 生产者
    private int remove = 0; // 下一次移除元素的位置 - 消费者

    public SynchronizedQueue() {
        this(DEFAULT_SIZE);
    }

    public SynchronizedQueue(int initialSize) {
        queue = new Object[initialSize];
        size = initialSize;
    }


    public synchronized boolean offer(T t) {
        queue[insert++] = t;

        // Wrap 到达数组末尾,下一次在0位置插入 
        if (insert == size) {
            insert = 0;
        }
        // 插入位置和移除位置相同,数组已满,则扩容
        if (insert == remove) {
            expand();
        }
        return true;
    }
    /*
        对于循环数组来说：insert == remove 时，如何区分 数组到底是为空还是满呢？
        对于一般的环形队列来说：数组不能填满，需要留一个位置来区分上面所讲的问题，但是这里tomcat没有预留一个位置
        在这里的关键点在于：offer()是先插入在判断的,什么意思？比如数组长度为4，那么插入到第4个的时候，size = 4 = insert -> 然后 insert = 0
        如果此时remove = 0 , 那么说明数组满了，此时就会触发扩容,扩容后的remove = 0,insert = size,size = newSize
        所以 poll()的时候能够正常工作
        和 Disruptor对比，这里没有
    */
    public synchronized T poll() {
        // 插入位置和移除位置相等,数组为空 {等等 - 在这里 insert == remove,那么数组到底是空还是满呢？这里的设计有点巧妙}
        if (insert == remove) {
            // empty
            return null;
        }

        @SuppressWarnings("unchecked")
        T result = (T) queue[remove];
        queue[remove] = null;
        remove++;

        // Wrap
        if (remove == size) {
            remove = 0;
        }

        return result;
    }

    private void expand() {
        int newSize = size * 2;
        Object[] newQueue = new Object[newSize];

        System.arraycopy(queue, insert, newQueue, 0, size - insert);
        System.arraycopy(queue, 0, newQueue, size - insert, insert);

        insert = size;
        remove = 0;
        queue = newQueue;
        size = newSize;
    }

    public synchronized int size() {
        int result = insert - remove;
        if (result < 0) {
            result += size;
        }
        return result;
    }

    public synchronized void clear() {
        queue = new Object[size];
        insert = 0;
        remove = 0;
    }
}
