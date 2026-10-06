package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.detect.RuleSet;
import com.github.guoyyit.networkidsjava.engine.FlowResult;
import com.github.guoyyit.networkidsjava.engine.FlowTable;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.engine.ProcessResult;
import com.github.guoyyit.networkidsjava.engine.TcpFlow;
import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 容量驱逐与老化回收时在途重组数据的处理。 */
class FlowEvictionTest {

    @TempDir
    Path tempDir;

    private Rule evilRule() {
        return new Rule("EVIL", "evil match", null,
                "evil".getBytes(StandardCharsets.UTF_8), false);
    }

    private RuleSet evilRuleSet() {
        RuleSet rs = new RuleSet();
        rs.addOrUpdate(evilRule());
        return rs;
    }

    /** 握手 + 一个带前导空洞(偏移 3)的乱序数据段 "xxevil"，数据滞留在重组缓存中。 */
    private void feedWithBufferedData(TcpFlow flow, RuleSet rs) {
        flow.handle(Packets.c2s(1, 1000, 1000, 0, TcpFlags.SYN, null), rs);
        flow.handle(Packets.s2c(2, 1001, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null), rs);
        flow.handle(Packets.c2s(3, 1002, 1001, 5001, TcpFlags.ACK, null), rs);
        // 相对偏移 3，留下 [0,3) 空洞，"xxevil" 滞留缓存。
        flow.handle(Packets.c2s(4, 1003, 1004, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "xxevil"), rs);
    }

    @Test
    void flushPendingDeliversBufferedFragmentsInOrder() {
        IdsConfig config = new IdsConfig();
        FlowKey key = new FlowKey(Packets.C_IP, Packets.C_PORT, Packets.S_IP, Packets.S_PORT);
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        RuleSet rs = new RuleSet();
        rs.addOrUpdate(new Rule("W", "m", null,
                "WORLD".getBytes(StandardCharsets.UTF_8), false));

        flow.handle(Packets.c2s(1, 1000, 1000, 0, TcpFlags.SYN, null), rs);
        flow.handle(Packets.s2c(2, 1001, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null), rs);
        flow.handle(Packets.c2s(3, 1002, 1001, 5001, TcpFlags.ACK, null), rs);
        // 偏移 0: "hello " 立即交付。
        FlowResult first = flow.handle(Packets.c2s(4, 1003, 1001, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "hello "), rs);
        assertEquals(1, first.getChunks().size());
        // 偏移 11: "WORLD" 滞留(空洞 [6,11))；偏移 8: "xy" 滞留(空洞 [6,8))。
        flow.handle(Packets.c2s(5, 1004, 1012, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "WORLD"), rs);
        flow.handle(Packets.c2s(6, 1005, 1009, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "xy"), rs);

        FlowResult flushed = flow.flushPending(rs, 2000L, 99L);
        assertEquals(2, flushed.getChunks().size());
        // 按序列号升序尽力交付，偏移保持流内绝对位置。
        assertEquals(8L, flushed.getChunks().get(0).getStreamOffset());
        assertEquals("xy", new String(flushed.getChunks().get(0).getData(),
                StandardCharsets.UTF_8));
        assertEquals(11L, flushed.getChunks().get(1).getStreamOffset());
        assertEquals("WORLD", new String(flushed.getChunks().get(1).getData(),
                StandardCharsets.UTF_8));
        assertEquals(1, flushed.getAlerts().size());
        assertEquals(11L, flushed.getAlerts().get(0).getStreamOffset());
        assertEquals("W", flushed.getAlerts().get(0).getRuleId());
    }

    @Test
    void capacityEvictionHandsVictimBackWithInFlightData() {
        IdsConfig config = new IdsConfig();
        config.setMaxFlows(1);
        config.setIdleTimeoutMillis(50L);
        FlowTable table = new FlowTable(config);
        RuleSet rs = evilRuleSet();

        FlowKey keyA = new FlowKey(Packets.C_IP, Packets.C_PORT, Packets.S_IP, Packets.S_PORT);
        TcpFlow flowA = table.acquire(keyA, 1000L).getFlow();
        assertNotNull(flowA);
        feedWithBufferedData(flowA, rs);

        // 表满，A 空闲到期被驱逐；受害者必须交还给调用方处理在途数据。
        FlowKey keyB = new FlowKey("10.0.0.9", 50000, Packets.S_IP, Packets.S_PORT);
        FlowTable.AcquireResult acquired = table.acquire(keyB, 2000L);
        assertNotNull(acquired.getFlow());
        assertEquals(1, acquired.getEvictedFlows().size());
        assertNull(table.get(keyA));

        FlowResult flushed = acquired.getEvictedFlows().get(0)
                .flushPending(rs, 2000L, 99L);
        assertEquals(1, flushed.getChunks().size());
        assertEquals(3L, flushed.getChunks().get(0).getStreamOffset());
        assertEquals("xxevil", new String(flushed.getChunks().get(0).getData(),
                StandardCharsets.UTF_8));
        assertEquals(1, flushed.getAlerts().size());
        assertEquals("EVIL", flushed.getAlerts().get(0).getRuleId());
        assertEquals(5L, flushed.getAlerts().get(0).getStreamOffset());
    }

    @Test
    void agingReclaimFlushesInFlightDataThroughEngine() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("ids-state").toString());
        config.setCommitEveryNPackets(10_000L);
        config.setIdleTimeoutMillis(50L);

        try (IdsEngine engine = new IdsEngine(config)) {
            engine.open();
            engine.addRule(evilRule());

            // 连接 A：握手 + 滞留的乱序数据 "xxevil"(偏移 3)。
            engine.process(Packets.c2s(1, 1000, 1000, 0, TcpFlags.SYN, null));
            engine.process(Packets.s2c(2, 1001, 5000, 1001,
                    TcpFlags.SYN | TcpFlags.ACK, null));
            engine.process(Packets.c2s(3, 1002, 1001, 5001, TcpFlags.ACK, null));
            ProcessResult data = engine.process(Packets.c2s(4, 1003, 1004, 5001,
                    TcpFlags.ACK | TcpFlags.PSH, "xxevil"));
            assertTrue(data.getAlerts().isEmpty(), "数据滞留未交付时不应有命中");

            // 连接 B 的报文触发老化回收，A 的在途数据必须先处理再释放。
            ProcessResult tick = engine.process(Packets.of(5, 2000,
                    "10.0.0.9", 50000, Packets.S_IP, Packets.S_PORT,
                    100, 0, TcpFlags.SYN, null));

            assertEquals(1, tick.getReassembledChunks().size(),
                    "老化回收必须交付在途重组数据");
            FlowResult.ReassembledChunk chunk = tick.getReassembledChunks().get(0);
            assertEquals(Direction.FORWARD, chunk.getDirection());
            assertEquals(3L, chunk.getStreamOffset());
            assertEquals("xxevil", new String(chunk.getData(), StandardCharsets.UTF_8));

            assertEquals(1, tick.getAlerts().size(), "在途数据中的命中不得丢失");
            Alert hit = tick.getAlerts().get(0);
            assertEquals("EVIL", hit.getRuleId());
            assertEquals(5L, hit.getStreamOffset());
            assertTrue(hit.getMatchedContext().contains("xxevil"));
            assertEquals(new FlowKey(Packets.C_IP, Packets.C_PORT,
                    Packets.S_IP, Packets.S_PORT).identity(),
                    hit.getFlowKey().identity());
        }
    }

    @Test
    void agingReclaimResultMatchesSequentialProcessing() {
        // 同一固定输入处理两次，回收路径产出的命中与内容必须逐条一致(可复现)。
        List<String> run1 = replayAgingRun();
        List<String> run2 = replayAgingRun();
        assertEquals(run1, run2);
        assertEquals(1, run1.size(), "滞留数据在老化回收时应产生且仅产生一次命中");
    }

    private List<String> replayAgingRun() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("state-" + System.nanoTime()).toString());
        config.setCommitEveryNPackets(10_000L);
        config.setIdleTimeoutMillis(50L);
        List<String> out = new java.util.ArrayList<>();
        try (IdsEngine engine = new IdsEngine(config)) {
            engine.open();
            engine.addRule(evilRule());
            List<Packet> packets = List.of(
                    Packets.c2s(1, 1000, 1000, 0, TcpFlags.SYN, null),
                    Packets.s2c(2, 1001, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null),
                    Packets.c2s(3, 1002, 1001, 5001, TcpFlags.ACK, null),
                    Packets.c2s(4, 1003, 1004, 5001,
                            TcpFlags.ACK | TcpFlags.PSH, "xxevil"),
                    Packets.of(5, 2000, "10.0.0.9", 50000, Packets.S_IP, Packets.S_PORT,
                            100, 0, TcpFlags.SYN, null));
            for (Packet p : packets) {
                ProcessResult r = engine.process(p);
                for (Alert a : r.getAlerts()) {
                    out.add(a.identity() + "|" + a.getMatchedContext());
                }
            }
        }
        return out;
    }
}
