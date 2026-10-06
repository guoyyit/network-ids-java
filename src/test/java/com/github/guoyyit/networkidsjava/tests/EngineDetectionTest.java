package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.detect.RuleParser;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.engine.ProcessResult;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EngineDetectionTest {

    @TempDir
    Path tempDir;

    private IdsConfig config() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("ids-state").toString());
        config.setCommitEveryNPackets(10_000L);
        return config;
    }

    /** 构造一条完整连接上的若干数据报文(序号按 data 偏移)。 */
    private List<Packet> connectionWithData(List<String> chunks, long baseSeq) {
        List<Packet> packets = new ArrayList<>();
        long order = 1;
        long ts = 1000L;
        packets.add(Packets.c2s(order++, ts++, 1000, 0, TcpFlags.SYN, null));
        packets.add(Packets.s2c(order++, ts++, 5000, 1001,
                TcpFlags.SYN | TcpFlags.ACK, null));
        packets.add(Packets.c2s(order++, ts++, 1001, 5001, TcpFlags.ACK, null));
        long seq = baseSeq;
        for (String chunk : chunks) {
            packets.add(Packets.c2s(order++, ts, seq, 5001,
                    TcpFlags.ACK | TcpFlags.PSH, chunk));
            seq += chunk.length();
        }
        return packets;
    }

    @Test
    void detectsFixedContentAcrossInOrderPackets() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(RuleParser.parse("R1: content:malware; message:found malware"));
            List<AggregatedAlert> alerts =
                    engine.runReplay(connectionWithData(List.of("AAA", "mal", "wareBBB"), 1001));
            assertEquals(1, alerts.size());
            assertEquals("R1", alerts.get(0).getRuleId());
        }
    }

    @Test
    void detectsAcrossPacketBoundaryWhenReordered() {
        // 特征 "secret" 跨两段，且后段先到(乱序)，重组后仍需命中一次。
        List<Packet> packets =
                connectionWithData(List.of("XXsecretYY"), 1001);
        // 将数据段拆成两半并乱序注入。
        List<Packet> reordered = reorderAndSplitData(packets, "XXsecretYY", "XXse", "cretYY");

        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(new Rule("R2", "secret leak", null,
                    "secret".getBytes(), false));
            List<AggregatedAlert> alerts = engine.runReplay(reordered);
            assertEquals(1, alerts.size());
            assertTrue(alerts.get(0).getFirstContext().contains("secret"));
        }
    }

    private List<Packet> reorderAndSplitData(List<Packet> handshake,
                                             String original, String first, String second) {
        // handshakes 前三个 + 一个数据段；这里重建为两个乱序数据段。
        List<Packet> out = new ArrayList<>(handshake.subList(0, 3));
        long base = 1001;
        Packet later = Packets.c2s(5, 1006L, base + first.length(), 5001,
                TcpFlags.ACK | TcpFlags.PSH, second);
        Packet earlier = Packets.c2s(4, 1005L, base, 5001,
                TcpFlags.ACK | TcpFlags.PSH, first);
        out.add(later);
        out.add(earlier);
        return out;
    }

    @Test
    void replayIsDeterministic() {
        Rule rule = RuleParser.parse("R3: content:attack;");
        List<Packet> packets = connectionWithData(
                Collections.nCopies(3, "attack-payload"), 1001);

        List<String> run1 = new ArrayList<>();
        List<String> run2 = new ArrayList<>();
        for (int run = 0; run < 2; run++) {
            Path dir = tempDir.resolve("run-" + run + "-" + System.nanoTime());
            IdsConfig cfg = config();
            cfg.setStateDir(dir.toString());
            try (IdsEngine engine = new IdsEngine(cfg)) {
                engine.open();
                engine.addRule(rule);
                List<String> sink = run == 0 ? run1 : run2;
                for (AggregatedAlert alert : engine.runReplay(packets)) {
                    sink.add(alert.getRuleId() + ":" + alert.getHitCount()
                            + ":" + alert.getFirstHitMillis()
                            + ":" + alert.getLastHitMillis());
                }
            }
        }
        assertEquals(run1, run2);
    }

    @Test
    void sameStartSegmentsShortThenLongDeliverFullContent() {
        // 同起点不同长度：短段先到(被洞缓存)，长段随后；补洞后必须交付完整内容。
        assertSameStartEngineResult(true);
    }

    @Test
    void sameStartSegmentsLongThenShortDeliverFullContent() {
        // 同起点不同长度：长段先到(被洞缓存)，短段随后不得截断。
        assertSameStartEngineResult(false);
    }

    /**
     * 引擎级验证：无论同起点两段谁先到达，重组交付的完整内容都是
     * "0123456789HELLOWORLD"，且规则 HELLOWORLD 在偏移 10 恰好命中一次。
     */
    private void assertSameStartEngineResult(boolean shortFirst) {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(new Rule("R-HW", "hello world", null,
                    "HELLOWORLD".getBytes(), false));
            List<Packet> packets = new ArrayList<>();
            packets.add(Packets.c2s(1, 1000, 1000, 0, TcpFlags.SYN, null));
            packets.add(Packets.s2c(2, 1001, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null));
            packets.add(Packets.c2s(3, 1002, 1001, 5001, TcpFlags.ACK, null));
            // 相对偏移 10 处同起点的两段(前方有洞，均被缓存)。
            Packet shortSeg = Packets.c2s(4, 1003, 1011, 5001,
                    TcpFlags.ACK | TcpFlags.PSH, "HELLO");
            Packet longSeg = Packets.c2s(5, 1004, 1011, 5001,
                    TcpFlags.ACK | TcpFlags.PSH, "HELLOWORLD");
            packets.add(shortFirst ? shortSeg : longSeg);
            packets.add(shortFirst ? longSeg : shortSeg);
            // 补洞：相对偏移 0-9。
            packets.add(Packets.c2s(6, 1005, 1001, 5001,
                    TcpFlags.ACK | TcpFlags.PSH, "0123456789"));

            StringBuilder delivered = new StringBuilder();
            List<com.github.guoyyit.networkidsjava.alert.Alert> hits = new ArrayList<>();
            for (Packet p : packets) {
                ProcessResult r = engine.process(p);
                for (var chunk : r.getChunks()) {
                    delivered.append(new String(chunk.getData(),
                            java.nio.charset.StandardCharsets.UTF_8));
                }
                hits.addAll(r.getAlerts());
            }
            assertEquals("0123456789HELLOWORLD", delivered.toString(),
                    "同起点段两种到达顺序的重组内容必须与按序到达一致");
            assertEquals(1, hits.size(), "HELLOWORLD 必须恰好命中一次: " + hits);
            assertEquals(10L, hits.get(0).getStreamOffset());
        }
    }
}
