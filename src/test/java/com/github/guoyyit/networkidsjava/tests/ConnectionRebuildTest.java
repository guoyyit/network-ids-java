package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.engine.ProcessResult;
import com.github.guoyyit.networkidsjava.model.AnomalyType;
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
 * 相同四元组连接快速结束并重建：新握手必须被正常接受，
 * 握手控制报文与紧随的数据报文不得被判非法；陈旧报文行为确定。
 */
class ConnectionRebuildTest {

    @TempDir
    Path tempDir;

    private IdsConfig config() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("ids-state-" + System.nanoTime()).toString());
        config.setCommitEveryNPackets(10_000L);
        return config;
    }

    private static Packet syn(long order, long ts, long seq) {
        return Packets.c2s(order, ts, seq, 0, TcpFlags.SYN, null);
    }

    private static Packet synAck(long order, long ts, long seq, long ack) {
        return Packets.s2c(order, ts, seq, ack, TcpFlags.SYN | TcpFlags.ACK, null);
    }

    private static Packet ackC(long order, long ts, long seq, long ack) {
        return Packets.c2s(order, ts, seq, ack, TcpFlags.ACK, null);
    }

    private static Packet dataC(long order, long ts, long seq, long ack, String body) {
        return Packets.c2s(order, ts, seq, ack, TcpFlags.ACK | TcpFlags.PSH, body);
    }

    private static List<Alert> alertsOf(List<ProcessResult> results) {
        List<Alert> all = new ArrayList<>();
        for (ProcessResult r : results) {
            all.addAll(r.getAlerts());
        }
        return all;
    }

    private static long anomalyCount(List<ProcessResult> results, AnomalyType type) {
        return results.stream()
                .flatMap(r -> r.getAnomalies().stream())
                .filter(a -> a.getType() == type)
                .count();
    }

    /** 四次挥手关闭(双方最终都进入 FIN_WAIT_2 收尾态)。 */
    private List<Packet> gracefulClose(long order, long ts, long cSeq, long sSeq) {
        List<Packet> p = new ArrayList<>();
        p.add(Packets.c2s(order++, ts++, cSeq, sSeq, TcpFlags.FIN | TcpFlags.ACK, null));
        p.add(Packets.s2c(order++, ts++, sSeq, cSeq + 1, TcpFlags.ACK, null));
        p.add(Packets.s2c(order++, ts++, sSeq, cSeq + 1, TcpFlags.FIN | TcpFlags.ACK, null));
        p.add(Packets.c2s(order++, ts++, cSeq + 1, sSeq + 1, TcpFlags.ACK, null));
        return p;
    }

    @Test
    void rebuildAfterGracefulCloseAcceptsNewHandshakeAndData() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(new Rule("R-EVIL", "evil", null,
                    "evil".getBytes(StandardCharsets.UTF_8), false));

            List<ProcessResult> results = new ArrayList<>();
            // 连接 1：ISN c=1000/s=5000，发送一次 evil 后四次挥手关闭。
            results.add(engine.process(syn(1, 1000, 1000)));
            results.add(engine.process(synAck(2, 1001, 5000, 1001)));
            results.add(engine.process(ackC(3, 1002, 1001, 5001)));
            results.add(engine.process(dataC(4, 1003, 1001, 5001, "evil")));
            for (Packet p : gracefulClose(5, 1004, 1005, 5001)) {
                results.add(engine.process(p));
            }

            // 连接 2：同四元组、全新 ISN(c=9000/s=7000)，紧随其后重建。
            List<ProcessResult> rebuild = new ArrayList<>();
            rebuild.add(engine.process(syn(9, 1008, 9000)));
            rebuild.add(engine.process(synAck(10, 1009, 7000, 9001)));
            rebuild.add(engine.process(ackC(11, 1010, 9001, 7001)));
            rebuild.add(engine.process(dataC(12, 1011, 9001, 7001, "evil")));

            // 新握手与数据全程不得出现任何异常分类。
            for (ProcessResult r : rebuild) {
                assertTrue(r.getAnomalies().isEmpty(),
                        "重建连接的握手/数据不得被判非法: " + r.getAnomalies());
            }

            // 两次连接各命中一次 evil；第二次命中的流内偏移必须基于新 ISN 从 0 开始。
            List<Alert> all = alertsOf(results);
            all.addAll(alertsOf(rebuild));
            assertEquals(2, all.size(), "新旧连接应各命中一次: " + all);
            assertEquals(0L, all.get(0).getStreamOffset());
            assertEquals(0L, all.get(1).getStreamOffset(),
                    "重建连接的命中偏移必须按新 ISN 归一化: " + all.get(1));
        }
    }

    @Test
    void rebuildAfterRstAcceptsNewHandshakeAndData() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(new Rule("R-EVIL", "evil", null,
                    "evil".getBytes(StandardCharsets.UTF_8), false));

            engine.process(syn(1, 1000, 1000));
            engine.process(synAck(2, 1001, 5000, 1001));
            engine.process(ackC(3, 1002, 1001, 5001));
            engine.process(dataC(4, 1003, 1001, 5001, "evil"));
            // RST 立即中止整条连接。
            engine.process(Packets.c2s(5, 1004, 1005, 5001, TcpFlags.RST, null));

            List<ProcessResult> rebuild = new ArrayList<>();
            rebuild.add(engine.process(syn(6, 1005, 9000)));
            rebuild.add(engine.process(synAck(7, 1006, 7000, 9001)));
            rebuild.add(engine.process(ackC(8, 1007, 9001, 7001)));
            rebuild.add(engine.process(dataC(9, 1008, 9001, 7001, "evil")));

            for (ProcessResult r : rebuild) {
                assertTrue(r.getAnomalies().isEmpty(),
                        "RST 后重建连接的握手/数据不得被判非法: " + r.getAnomalies());
            }
            List<Alert> hits = alertsOf(rebuild);
            assertEquals(1, hits.size(), "重建连接上的数据必须命中: " + hits);
            assertEquals(0L, hits.get(0).getStreamOffset());
        }
    }

    @Test
    void stalePacketsAreClassifiedDeterministicallyAndDoNotCorruptNewConnection() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(new Rule("R-EVIL", "evil", null,
                    "evil".getBytes(StandardCharsets.UTF_8), false));

            // 连接 1 建立并发送数据后四次挥手关闭。
            engine.process(syn(1, 1000, 1000));
            engine.process(synAck(2, 1001, 5000, 1001));
            engine.process(ackC(3, 1002, 1001, 5001));
            engine.process(dataC(4, 1003, 1001, 5001, "evil"));
            for (Packet p : gracefulClose(5, 1004, 1005, 5001)) {
                engine.process(p);
            }

            // 连接 2 开始重建。
            engine.process(syn(9, 1008, 9000));

            // 陈旧报文 1：旧连接的数据重传，在新握手完成前到达。
            ProcessResult staleDuringHandshake =
                    engine.process(dataC(10, 1009, 1001, 5001, "evil"));
            assertEquals(1, staleDuringHandshake.getAnomalies().stream()
                    .filter(a -> a.getType() == AnomalyType.DATA_ON_NON_ESTABLISHED)
                    .count(), "握手期间的陈旧数据必须被判为未建立状态数据");
            assertTrue(staleDuringHandshake.getAlerts().isEmpty());

            // 新握手继续完成，不受陈旧报文影响。
            List<ProcessResult> rest = new ArrayList<>();
            rest.add(engine.process(synAck(11, 1010, 7000, 9001)));
            rest.add(engine.process(ackC(12, 1011, 9001, 7001)));
            rest.add(engine.process(dataC(13, 1012, 9001, 7001, "evil")));

            // 陈旧报文 2：旧连接数据在新连接建立后到达(旧 ISN 空间，远小于已交付偏移)。
            ProcessResult staleAfter =
                    engine.process(dataC(14, 1013, 1001, 5001, "evil"));

            for (ProcessResult r : rest) {
                assertTrue(r.getAnomalies().isEmpty(),
                        "新连接握手不得受陈旧报文干扰: " + r.getAnomalies());
            }
            // 新连接数据恰好命中一次；陈旧重传不产生重复命中、不产生异常。
            List<Alert> hits = alertsOf(rest);
            assertEquals(1, hits.size(), "新连接数据必须恰好命中一次: " + hits);
            assertEquals(0L, hits.get(0).getStreamOffset());
            assertTrue(staleAfter.getAlerts().isEmpty(),
                    "已交付区间的陈旧重传不得重复命中");
            assertTrue(staleAfter.getAnomalies().isEmpty());
        }
    }

    @Test
    void rebuildIsDeterministicAcrossReplays() {
        List<String> run1 = replayRebuild();
        List<String> run2 = replayRebuild();
        assertEquals(run1, run2, "相同输入的重建流程结果必须可复现");
    }

    private List<String> replayRebuild() {
        List<String> sink = new ArrayList<>();
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(new Rule("R-EVIL", "evil", null,
                    "evil".getBytes(StandardCharsets.UTF_8), false));
            List<Packet> packets = new ArrayList<>();
            packets.add(syn(1, 1000, 1000));
            packets.add(synAck(2, 1001, 5000, 1001));
            packets.add(ackC(3, 1002, 1001, 5001));
            packets.add(dataC(4, 1003, 1001, 5001, "evil"));
            packets.addAll(gracefulClose(5, 1004, 1005, 5001));
            packets.add(syn(9, 1008, 9000));
            packets.add(synAck(10, 1009, 7000, 9001));
            packets.add(ackC(11, 1010, 9001, 7001));
            packets.add(dataC(12, 1011, 9001, 7001, "evil"));
            for (Packet p : packets) {
                ProcessResult r = engine.process(p);
                for (Alert a : r.getAlerts()) {
                    sink.add(a.getRuleId() + "@" + a.getStreamOffset() + "#" + a.getCaptureOrder());
                }
                for (var a : r.getAnomalies()) {
                    sink.add("ANOMALY:" + a.getType() + "#" + a.getCaptureOrder());
                }
            }
        }
        return sink;
    }
}
