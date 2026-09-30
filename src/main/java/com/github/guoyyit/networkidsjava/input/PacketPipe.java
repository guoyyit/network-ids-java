package com.github.guoyyit.networkidsjava.input;

import com.github.guoyyit.networkidsjava.model.Packet;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * 内存报文管道：生产者注入模拟报文，引擎/消费端取出处理。
 * 也可直接把报文列表喂给引擎，不依赖真实网络。
 */
public final class PacketPipe {
    private final BlockingQueue<Packet> queue = new LinkedBlockingQueue<>();
    private volatile boolean closed;

    public void inject(Packet packet) throws InterruptedException {
        if (closed) {
            throw new IllegalStateException("管道已关闭");
        }
        queue.put(packet);
    }

    public Packet take() throws InterruptedException {
        Packet packet = queue.poll();
        if (packet != null) {
            return packet;
        }
        if (closed) {
            return null;
        }
        while (!closed) {
            Packet polled = queue.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS);
            if (polled != null) {
                return polled;
            }
        }
        return queue.poll();
    }

    public void close() {
        closed = true;
    }

    public int size() {
        return queue.size();
    }
}
