package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.engine.FlowResult;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.engine.ProcessResult;
import com.github.guoyyit.networkidsjava.model.AnomalyEvent;
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

/** 同四元组连接快速结束并重建的完整握手与数据流程(引擎级)。 */
class ConnectionReconnectTest {

    @TempDir
    Path tempDir;

    private IdsConfig config() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("state-" + System.nanoTime()).toString());
        config.setCommitEveryNPackets(10_000L);
        return config;
    }

    private Rule evilRule() {
        return new Rule("EVIL", "evil match", null,
                "evil".getBytes(StandardCharsets.UTF_8), false);
    }

    /** 旧连接(RST 结束) + 同四元组新连接(新 ISN) 各携带一次特征。 */
    private List<Packet> reconnectReplay() {
        List<Packet> packets = new ArrayList<>();
        // 旧连接：握手 + 数据 + RST。
        packets.add(Packets.c2s(1, 1001, 1000, 0, TcpFlags.SYN, null));
        packets.add(Packets.s2c(2, 1002, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null));
        packets.add(Packets.c2s(3, 1003, 1001, 5001, TcpFlags.ACK, null));
        packets.add(Packets.c2s(4, 1004, 1001, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "evil-one"));
        packets.add(Packets.c2s(5, 1005, 1009, 5001, TcpFlags.RST, null));
        // 新连接：同四元组、新 ISN 的完整握手 + 数据。
        packets.add(Packets.c2s(6, 1006, 9000, 0, TcpFlags.SYN, null));
        packets.add(Packets.s2c(7, 1007, 3000, 9001, TcpFlags.SYN | TcpFlags.ACK, null));
        packets.add(Packets.c2s(8, 1008, 9001, 3001, TcpFlags.ACK, null));
        packets.add(Packets.c2s(9, 1009, 9001, 3001,
                TcpFlags.ACK | TcpFlags.PSH, "evil-two"));
        return packets;
    }

    @Test
    void reconnectAfterRstDeliversDataAndHitsOnBothConnections() {
        List<Alert> hits = new ArrayList<>();
        List<String> chunks = new ArrayList<>();
        List<AnomalyEvent> anomalies = new ArrayList<>();
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(evilRule());
            for (Packet p : reconnectReplay()) {
                ProcessResult r = engine.process(p);
                hits.addAll(r.getAlerts());
                anomalies.addAll(r.getAnomalies());
                for (FlowResult.ReassembledChunk c : r.getReassembledChunks()) {
                    chunks.add(c.getStreamOffset() + ":"
                            + new String(c.getData(), StandardCharsets.UTF_8));
                }
            }
        }

        // 两条连接各自从偏移 0 交付数据。
        assertEquals(List.of("0:evil-one", "0:evil-two"), chunks);

        // 两次命中：分属两条连接，流内偏移都从 0 开始。
        assertEquals(2, hits.size());
        assertEquals(0L, hits.get(0).getStreamOffset());
        assertTrue(hits.get(0).getMatchedContext().contains("evil-one"));
        assertEquals(0L, hits.get(1).getStreamOffset());
        assertTrue(hits.get(1).getMatchedContext().contains("evil-two"));

        // 重建握手与数据全程不得产生非法/未建立类异常。
        assertTrue(anomalies.isEmpty(), "重建流程不应产生异常: " + anomalies);
    }

    @Test
    void reconnectReplayIsDeterministic() {
        List<String> run1 = replayAlertIdentities();
        List<String> run2 = replayAlertIdentities();
        assertEquals(run1, run2);
        assertEquals(2, run1.size());
    }

    @Test
    void aggregatedOutputContainsBothConnections() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(evilRule());
            List<AggregatedAlert> all = engine.runReplay(reconnectReplay());
            assertEquals(1, all.size(), "同窗口同规则同方向应聚合为一条");
            assertEquals(2L, all.get(0).getHitCount(), "两条连接的命中都应计入");
            assertEquals("EVIL", all.get(0).getRuleId());
        }
    }

    private List<String> replayAlertIdentities() {
        List<String> out = new ArrayList<>();
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(evilRule());
            for (Packet p : reconnectReplay()) {
                for (Alert a : engine.process(p).getAlerts()) {
                    out.add(a.identity());
                }
            }
        }
        return out;
    }
}
