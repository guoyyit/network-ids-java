package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.engine.ProcessResult;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyTest {

    @TempDir
    Path tempDir;

    /**
     * 多个线程并发注入不同连接的报文，同时另一线程持续触发老化回收。
     * 要求：不抛异常、不状态损坏、引擎串行化处理后内存有界。
     */
    @Test
    void concurrentDetectionAndAgingIsSafe() throws Exception {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("state").toString());
        config.setCommitEveryNPackets(500L);
        config.setIdleTimeoutMillis(1);
        config.setMaxFlows(200);

        AtomicBoolean failed = new AtomicBoolean(false);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();

        try (IdsEngine engine = new IdsEngine(config)) {
            engine.open();
            engine.addRule(new Rule("EVIL", "m", null,
                    "evil".getBytes(StandardCharsets.UTF_8), false));

            int threads = 8;
            CountDownLatch start = new CountDownLatch(1);
            ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
            AtomicLong orderSeq = new AtomicLong(1);

            for (int t = 0; t < threads; t++) {
                final int client = t;
                pool.submit(() -> {
                    try {
                        start.await();
                        String ip = "10.0.0." + (10 + client);
                        submitBurst(engine, ip, 50000 + client, orderSeq);
                    } catch (Throwable e) {
                        failed.set(true);
                        errors.add(e);
                    }
                });
            }
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 200; i++) {
                        // 用一个很新的事件时间持续触发老化回收。
                        Packet tick = Packets.of(-(i + 1L), 10_000_000L + i,
                                "9.9.9.9", 1, "9.9.9.8", 1,
                                0, 0, TcpFlags.SYN, null);
                        engine.process(tick);
                    }
                } catch (Throwable e) {
                    failed.set(true);
                    errors.add(e);
                }
            });

            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        }
        errors.forEach(Throwable::printStackTrace);
        assertTrue(!failed.get(), "并发处理不应出现异常: " + errors);
    }

    /**
     * 并发处理互不相干的连接(无老化干扰)时，最终命中集合与聚合结果
     * 必须与逐条顺序处理完全一致。
     */
    @Test
    void concurrentProcessingMatchesSequentialResults() throws Exception {
        int flows = 8;
        List<Packet> sequential = new ArrayList<>();
        for (int t = 0; t < flows; t++) {
            String ip = "10.0.0." + (10 + t);
            int port = 50000 + t;
            long base = (t + 1L) * 10;
            sequential.add(Packets.of(base + 1, 1000 + base, ip, port, "10.1.0.1", 80,
                    1000, 0, TcpFlags.SYN, null));
            sequential.add(Packets.of(base + 2, 1001 + base, "10.1.0.1", 80, ip, port,
                    5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null));
            sequential.add(Packets.of(base + 3, 1002 + base, ip, port, "10.1.0.1", 80,
                    1001, 5001, TcpFlags.ACK, null));
            sequential.add(Packets.of(base + 4, 1003 + base, ip, port, "10.1.0.1", 80,
                    1001, 5001, TcpFlags.ACK | TcpFlags.PSH, "evil"));
        }

        List<String> sequentialAlerts = runSequential(sequential);

        // 并发：每个连接一个线程，共用引擎(引擎串行化处理)。
        List<String> concurrentAlerts = new java.util.concurrent.CopyOnWriteArrayList<>();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(flows);
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("state-concurrent").toString());
        config.setCommitEveryNPackets(10_000L);
        try (IdsEngine engine = new IdsEngine(config)) {
            engine.open();
            engine.addRule(new Rule("EVIL", "m", null,
                    "evil".getBytes(StandardCharsets.UTF_8), false));
            for (int t = 0; t < flows; t++) {
                final int index = t;
                pool.submit(() -> {
                    try {
                        start.await();
                        for (int i = index * 4; i < index * 4 + 4; i++) {
                            ProcessResult r = engine.process(sequential.get(i));
                            for (var a : r.getAlerts()) {
                                concurrentAlerts.add(a.identity());
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        }

        List<String> sortedConcurrent = new ArrayList<>(concurrentAlerts);
        List<String> sortedSequential = new ArrayList<>(sequentialAlerts);
        java.util.Collections.sort(sortedConcurrent);
        java.util.Collections.sort(sortedSequential);
        assertEquals(sortedSequential, sortedConcurrent,
                "并发处理的命中集合必须与顺序处理一致");
        assertEquals(flows, sortedConcurrent.size());
    }

    private List<String> runSequential(List<Packet> packets) {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("state-sequential").toString());
        config.setCommitEveryNPackets(10_000L);
        List<String> alerts = new ArrayList<>();
        try (IdsEngine engine = new IdsEngine(config)) {
            engine.open();
            engine.addRule(new Rule("EVIL", "m", null,
                    "evil".getBytes(StandardCharsets.UTF_8), false));
            for (Packet p : packets) {
                for (var a : engine.process(p).getAlerts()) {
                    alerts.add(a.identity());
                }
            }
        }
        return alerts;
    }

    /** 为一个客户端提交握手 + 若干数据报文；order 全局唯一递增。 */
    private void submitBurst(IdsEngine engine, String clientIp, int clientPort,
                             AtomicLong orderSeq) {
        long synOrder = orderSeq.getAndIncrement();
        engine.process(Packets.of(synOrder, 2000L + synOrder,
                clientIp, clientPort, "10.1.0.1", 80,
                1000, 0, TcpFlags.SYN, null));
        long synAckOrder = orderSeq.getAndIncrement();
        engine.process(Packets.of(synAckOrder, 2000L + synAckOrder,
                "10.1.0.1", 80, clientIp, clientPort,
                5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null));
        long ackOrder = orderSeq.getAndIncrement();
        engine.process(Packets.of(ackOrder, 2000L + ackOrder,
                clientIp, clientPort, "10.1.0.1", 80,
                1001, 5001, TcpFlags.ACK, null));
        for (int i = 0; i < 5; i++) {
            long order = orderSeq.getAndIncrement();
            ProcessResult result = engine.process(Packets.of(order, 2000L + order,
                    clientIp, clientPort, "10.1.0.1", 80,
                    1001L + i * 4, 5001, TcpFlags.ACK | TcpFlags.PSH,
                    i % 2 == 0 ? "evil" : "safe"));
            // 命中或被回收都必须是确定、无异常的结果。
            if (!result.getAnomalies().isEmpty()) {
                // 容量类异常允许，但不应抛出。
            }
        }
    }
}
