package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.detect.RuleSet;
import com.github.guoyyit.networkidsjava.engine.FlowResult;
import com.github.guoyyit.networkidsjava.engine.FlowTable;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.engine.ProcessResult;
import com.github.guoyyit.networkidsjava.engine.TcpFlow;
import com.github.guoyyit.networkidsjava.model.AnomalyType;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 容量驱逐与老化回收：连接在途重组数据必须先排空检测再释放，
 * 命中不丢失、聚合不错乱，且结果与逐条顺序处理一致。
 */
class EvictionFlushTest {

    @TempDir
    Path tempDir;

    private IdsConfig config() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("ids-state-" + System.nanoTime()).toString());
        config.setCommitEveryNPackets(10_000L);
        config.setIdleTimeoutMillis(1000L);
        return config;
    }

    private static Rule rule(String id, String content) {
        return new Rule(id, content, null,
                content.getBytes(StandardCharsets.UTF_8), false);
    }

    /** 客户端握手(isn=1000) + 一段立即交付数据 + 一段洞后缓存数据。 */
    private static List<Packet> handshakeWithGappedData(
            String clientIp, int clientPort,
            long order, long ts, String delivered, String buffered, int gapStart) {
        List<Packet> p = new ArrayList<>();
        p.add(Packets.of(order, ts, clientIp, clientPort, Packets.S_IP, Packets.S_PORT,
                1000, 0, TcpFlags.SYN, null));
        p.add(Packets.of(order + 1, ts + 1, Packets.S_IP, Packets.S_PORT,
                clientIp, clientPort, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null));
        p.add(Packets.of(order + 2, ts + 2, clientIp, clientPort, Packets.S_IP, Packets.S_PORT,
                1001, 5001, TcpFlags.ACK, null));
        // 立即交付段：相对偏移 0 起。
        p.add(Packets.of(order + 3, ts + 3, clientIp, clientPort, Packets.S_IP, Packets.S_PORT,
                1001, 5001, TcpFlags.ACK | TcpFlags.PSH, delivered));
        // 洞后缓存段：相对偏移 gapStart 起(与交付段之间留洞)。
        p.add(Packets.of(order + 4, ts + 4, clientIp, clientPort, Packets.S_IP, Packets.S_PORT,
                1001L + gapStart, 5001, TcpFlags.ACK | TcpFlags.PSH, buffered));
        return p;
    }

    @Test
    void capacityEvictionFlushesInFlightDataBeforeRelease() {
        // 容量驱逐路径(流表级)：被驱逐连接的在途数据必须可经收尾检测产出命中。
        IdsConfig config = config();
        config.setMaxFlows(1);
        config.setIdleTimeoutMillis(Long.MAX_VALUE);
        config.setZombieTimeoutMillis(Long.MAX_VALUE);
        config.setMaxFlowLifetimeMillis(Long.MAX_VALUE);
        FlowTable table = new FlowTable(config);
        RuleSet rules = new RuleSet();
        rules.addOrUpdate(rule("R-EVIL", "evil"));

        FlowKey keyA = new FlowKey(Packets.C_IP, Packets.C_PORT, Packets.S_IP, Packets.S_PORT);
        TcpFlow flowA = table.acquire(keyA, 1000L).getFlow();
        for (Packet p : handshakeWithGappedData(Packets.C_IP, Packets.C_PORT,
                1, 1000, "GET ", "evil", 8)) {
            flowA.handle(p, rules);
        }
        // 关闭 A 使其成为容量回收的优先受害者。
        flowA.handle(Packets.c2s(6, 1005, 1005, 5001, TcpFlags.RST, null), rules);

        FlowKey keyB = new FlowKey("10.0.0.9", 50000, Packets.S_IP, Packets.S_PORT);
        FlowTable.AcquireResult acquired = table.acquire(keyB, 2000L);
        assertEquals(1, acquired.getEvicted().size(), "容量满必须驱逐已关闭的 A");
        assertTrue(acquired.getFlow() != null);

        // 收尾：排空在途数据并检测。
        FlowResult flushed = acquired.getEvicted().get(0).flushPending(rules, 2000L, 7L);
        assertEquals(1, flushed.getChunks().size());
        assertEquals(8L, flushed.getChunks().get(0).getStreamOffset());
        assertEquals("evil", new String(flushed.getChunks().get(0).getData(),
                StandardCharsets.UTF_8));
        assertEquals(1, flushed.getAlerts().size(), "洞后缓存的 evil 必须在回收时命中");
        Alert alert = flushed.getAlerts().get(0);
        assertEquals("R-EVIL", alert.getRuleId());
        assertEquals(8L, alert.getStreamOffset());
        assertEquals(2000L, alert.getTimestampMillis());
    }

    @Test
    void idleAgingFlushesInFlightDataThroughEnginePipeline() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(rule("R-PWD", "password"));
        try {
            // 连接 A：交付 "GET "，洞后缓存 "password"(相对偏移 8)。
            for (Packet p : handshakeWithGappedData(Packets.C_IP, Packets.C_PORT,
                    1, 1000, "GET ", "password", 8)) {
                engine.process(p);
            }
            // 连接 B 的报文把事件时间推进到 A 空闲超时之后，触发老化回收。
            ProcessResult trigger = engine.process(Packets.of(6, 2004,
                    "10.0.0.9", 50000, Packets.S_IP, Packets.S_PORT,
                    100, 0, TcpFlags.SYN, null));

            assertEquals(1, trigger.getAlerts().size(),
                    "老化回收必须把 A 的在途数据排空并命中: " + trigger.getAlerts());
            Alert alert = trigger.getAlerts().get(0);
            assertEquals("R-PWD", alert.getRuleId());
            assertEquals(8L, alert.getStreamOffset());
            assertEquals(2004L, alert.getTimestampMillis(),
                    "回收告警的时间戳取回收发生处的事件时间");
            assertEquals(1, trigger.getChunks().size());
            assertEquals(8L, trigger.getChunks().get(0).getStreamOffset());
            assertEquals("password",
                    new String(trigger.getChunks().get(0).getData(), StandardCharsets.UTF_8));

            // A 已被回收：其后续报文落到全新流上，按未建立状态分类。
            ProcessResult after = engine.process(Packets.c2s(7, 2005, 1001, 5001,
                    TcpFlags.ACK | TcpFlags.PSH, "more"));
            assertTrue(after.getAnomalies().stream().anyMatch(a ->
                    a.getType() == AnomalyType.DATA_AFTER_CLOSE
                            || a.getType() == AnomalyType.DATA_ON_NON_ESTABLISHED));
        } finally {
            engine.close();
        }
    }

    @Test
    void zombieAgingFlushesInFlightData() {
        // 僵死判定独立于空闲：把空闲阈值调大、僵死阈值调小，确保走僵死路径。
        IdsConfig config = config();
        config.setIdleTimeoutMillis(10_000L);
        config.setZombieTimeoutMillis(500L);
        IdsEngine engine = new IdsEngine(config);
        engine.open();
        engine.addRule(rule("R-EVIL", "evil"));
        try {
            for (Packet p : handshakeWithGappedData(Packets.C_IP, Packets.C_PORT,
                    1, 1000, "GET ", "evil", 8)) {
                engine.process(p);
            }
            // lastSeen=1004，事件时间推进到 1504：未达空闲阈值，达到僵死阈值。
            ProcessResult trigger = engine.process(Packets.of(6, 1504,
                    "10.0.0.9", 50000, Packets.S_IP, Packets.S_PORT,
                    100, 0, TcpFlags.SYN, null));
            assertEquals(1, trigger.getAlerts().size(),
                    "僵死回收必须排空在途数据并命中: " + trigger.getAlerts());
            assertEquals(8L, trigger.getAlerts().get(0).getStreamOffset());
            assertEquals("R-EVIL", trigger.getAlerts().get(0).getRuleId());
        } finally {
            engine.close();
        }
    }

    @Test
    void flushedAlertsAggregateIntoSameWindowWithoutDisorder() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(rule("R-EVIL", "evil"));
        List<AggregatedAlert> aggregated = new ArrayList<>();
        try {
            // 连接 A：先交付一次 evil(命中 1)，再洞后缓存一次 evil。
            for (Packet p : handshakeWithGappedData(Packets.C_IP, Packets.C_PORT,
                    1, 1000, "evil", "evil", 8)) {
                aggregated.addAll(engine.process(p).getAggregatedAlerts());
            }
            // 触发老化回收：命中 2 与命中 1 同键同窗口，必须合并。
            aggregated.addAll(engine.process(Packets.of(6, 2004,
                    "10.0.0.9", 50000, Packets.S_IP, Packets.S_PORT,
                    100, 0, TcpFlags.SYN, null)).getAggregatedAlerts());
            // 推进事件时间跨过窗口边界(该连接无命中，窗口留待关闭时刷出)。
            for (Packet p : handshakeWithGappedData("10.0.0.9", 50000,
                    7, 60_005, "safe", "safe", 8)) {
                aggregated.addAll(engine.process(p).getAggregatedAlerts());
            }
        } finally {
            engine.close();
            aggregated.addAll(engine.drainClosedTailAlerts());
        }

        List<AggregatedAlert> flowA = aggregated.stream()
                .filter(a -> a.getRuleId().equals("R-EVIL"))
                .toList();
        assertEquals(1, flowA.size(),
                "同一连接同一窗口内的命中(含回收排空产生的)必须合并为一条: " + flowA);
        assertEquals(2L, flowA.get(0).getHitCount());
        assertEquals(1003L, flowA.get(0).getFirstHitMillis());
        assertEquals(2004L, flowA.get(0).getLastHitMillis());
    }

    @Test
    void evictionFlushIsDeterministicAcrossReplays() {
        List<String> run1 = replayEvictionScenario();
        List<String> run2 = replayEvictionScenario();
        assertEquals(run1, run2, "含回收的固定回放结果必须逐条一致");
    }

    private List<String> replayEvictionScenario() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(rule("R-EVIL", "evil"));
        List<String> sink = new ArrayList<>();
        try {
            List<Packet> packets = new ArrayList<>();
            packets.addAll(handshakeWithGappedData(Packets.C_IP, Packets.C_PORT,
                    1, 1000, "GET ", "evil", 8));
            packets.add(Packets.of(6, 2004, "10.0.0.9", 50000,
                    Packets.S_IP, Packets.S_PORT, 100, 0, TcpFlags.SYN, null));
            for (Packet p : packets) {
                ProcessResult r = engine.process(p);
                for (Alert a : r.getAlerts()) {
                    sink.add(a.getRuleId() + "@" + a.getStreamOffset()
                            + " ts=" + a.getTimestampMillis());
                }
                for (var c : r.getChunks()) {
                    sink.add("chunk@" + c.getStreamOffset() + ":"
                            + new String(c.getData(), StandardCharsets.UTF_8));
                }
            }
        } finally {
            engine.close();
        }
        return sink;
    }
}
