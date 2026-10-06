package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
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
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 正常关闭路径：在途命中必须被提交或以可观察方式返回，不得静默丢弃。 */
class CloseFlushTest {

    @TempDir
    Path tempDir;

    private IdsConfig config() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("ids-state-" + System.nanoTime()).toString());
        config.setCommitEveryNPackets(10_000L);
        return config;
    }

    private static Rule evilRule() {
        return new Rule("R-EVIL", "evil", null,
                "evil".getBytes(StandardCharsets.UTF_8), false);
    }

    private static void handshake(IdsEngine engine, long order, long ts) {
        engine.process(Packets.c2s(order, ts, 1000, 0, TcpFlags.SYN, null));
        engine.process(Packets.s2c(order + 1, ts + 1, 5000, 1001,
                TcpFlags.SYN | TcpFlags.ACK, null));
        engine.process(Packets.c2s(order + 2, ts + 2, 1001, 5001, TcpFlags.ACK, null));
    }

    private static Packet evilData(long order, long ts, long seq) {
        return Packets.c2s(order, ts, seq, 5001, TcpFlags.ACK | TcpFlags.PSH, "evil");
    }

    @Test
    void closeFlushesUnexpiredWindowAggregates() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(evilRule());
        handshake(engine, 1, 1000);
        // 同一窗口内两次命中；事件时间不推进到窗口边界之外，窗口一直未关闭。
        ProcessResult r1 = engine.process(evilData(4, 1003, 1001));
        ProcessResult r2 = engine.process(evilData(5, 1004, 1005));
        assertEquals(1, r1.getAlerts().size());
        assertEquals(1, r2.getAlerts().size());
        assertTrue(r1.getAggregatedAlerts().isEmpty(), "窗口未到期不应提前刷出");
        assertTrue(r2.getAggregatedAlerts().isEmpty());
        assertTrue(engine.drainClosedTailAlerts().isEmpty(), "关闭前无尾部告警");

        engine.close();
        List<AggregatedAlert> tail = engine.drainClosedTailAlerts();
        assertEquals(1, tail.size(), "未到期窗口的聚合结果必须在关闭时刷出: " + tail);
        assertEquals(2L, tail.get(0).getHitCount());
    }

    @Test
    void closedTailIsObservableAndDrainedOnce() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(evilRule());
        handshake(engine, 1, 1000);
        engine.process(evilData(4, 1003, 1001));
        engine.process(evilData(5, 1004, 1005));

        engine.close();
        List<AggregatedAlert> tail = engine.drainClosedTailAlerts();
        assertEquals(1, tail.size(), "未到期窗口的聚合结果必须在关闭时刷出: " + tail);
        AggregatedAlert agg = tail.get(0);
        assertEquals("R-EVIL", agg.getRuleId());
        assertEquals(2L, agg.getHitCount(), "两次命中必须完整保留在尾部聚合中");
        assertEquals(1003L, agg.getFirstHitMillis());
        assertEquals(1004L, agg.getLastHitMillis());
        // 取出即清空；重复关闭幂等。
        assertTrue(engine.drainClosedTailAlerts().isEmpty());
        engine.close();
        assertTrue(engine.drainClosedTailAlerts().isEmpty());
    }

    @Test
    void processAfterCloseIsRejected() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(evilRule());
        handshake(engine, 1, 1000);
        engine.close();
        assertThrows(IllegalStateException.class,
                () -> engine.process(evilData(4, 1003, 1001)));
    }

    @Test
    void hitsInFlightDuringCloseAreNotLost() throws Exception {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(evilRule());

        CountDownLatch handshakeDone = new CountDownLatch(1);
        AtomicLong rawHits = new AtomicLong();
        AtomicLong aggregatedHits = new AtomicLong();
        AtomicReference<Throwable> failure = new AtomicReference<>();

        Thread producer = new Thread(() -> {
            try {
                handshake(engine, 1, 1000);
                handshakeDone.countDown();
                long order = 4;
                long seq = 1001;
                // 单窗口内持续制造命中，直到引擎关闭被拒绝。
                while (true) {
                    ProcessResult r = engine.process(evilData(order, 1000 + order, seq));
                    rawHits.addAndGet(r.getAlerts().size());
                    for (AggregatedAlert a : r.getAggregatedAlerts()) {
                        aggregatedHits.addAndGet(a.getHitCount());
                    }
                    order++;
                    seq += 4;
                }
            } catch (IllegalStateException closed) {
                // 关闭后拒绝处理：命中未被静默吞掉，而是明确反馈给调用方。
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        producer.start();
        assertTrue(handshakeDone.await(5, TimeUnit.SECONDS));
        // 让生产者处理若干报文后关闭引擎。
        Thread.sleep(50);
        engine.close();
        producer.join(5000);
        assertTrue(!producer.isAlive(), "关闭后生产者应因拒绝而退出");
        if (failure.get() != null) {
            throw new AssertionError("生产者线程出现异常", failure.get());
        }

        long tailHits = engine.drainClosedTailAlerts().stream()
                .mapToLong(AggregatedAlert::getHitCount).sum();
        assertTrue(rawHits.get() > 0, "测试应至少产生一次在途命中");
        assertEquals(rawHits.get(), aggregatedHits.get() + tailHits,
                "关闭前后已命中结果不得丢失：原始命中数必须等于已刷出+尾部刷出之和");
    }
}
