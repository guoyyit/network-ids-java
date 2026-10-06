package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.engine.FlowResult;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 同起点不同长度数据段在引擎级的两种到达顺序：
 * 最终重组内容与命中结果必须与按序到达完全一致。
 */
class SameStartSegmentTest {

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

    /**
     * 构造回放序列：握手后，偏移 5 处出现同起点段(短 "xye" 是长 "xyevilz" 的前缀)，
     * 最后由偏移 0 的段补洞。shortFirst 控制两个同起点段的到达顺序。
     */
    private List<Packet> replay(boolean shortFirst) {
        List<Packet> packets = new ArrayList<>();
        packets.add(Packets.c2s(1, 1001, 1000, 0, TcpFlags.SYN, null));
        packets.add(Packets.s2c(2, 1002, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null));
        packets.add(Packets.c2s(3, 1003, 1001, 5001, TcpFlags.ACK, null));
        Packet shortSeg = Packets.c2s(4, 1004, 1006, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "xye");
        Packet longSeg = Packets.c2s(5, 1005, 1006, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "xyevilz");
        if (shortFirst) {
            packets.add(shortSeg);
            packets.add(longSeg);
        } else {
            packets.add(longSeg);
            packets.add(shortSeg);
        }
        // 补 [0,5) 空洞，触发整体交付。
        packets.add(Packets.c2s(6, 1006, 1001, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "01234"));
        return packets;
    }

    private static final class RunOutput {
        final StringBuilder content = new StringBuilder();
        final List<String> alerts = new ArrayList<>();
        final List<String> anomalies = new ArrayList<>();
    }

    private RunOutput run(List<Packet> packets) {
        RunOutput out = new RunOutput();
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(evilRule());
            for (Packet p : packets) {
                ProcessResult r = engine.process(p);
                for (FlowResult.ReassembledChunk chunk : r.getReassembledChunks()) {
                    out.content.append(new String(chunk.getData(), StandardCharsets.UTF_8));
                }
                for (Alert a : r.getAlerts()) {
                    out.alerts.add(a.getRuleId() + "|" + a.getStreamOffset()
                            + "|" + a.getMatchedContext());
                }
                for (var an : r.getAnomalies()) {
                    out.anomalies.add(an.getType().name());
                }
            }
        }
        return out;
    }

    @Test
    void bothArrivalOrdersProduceIdenticalContentAndHits() {
        RunOutput shortFirst = run(replay(true));
        RunOutput longFirst = run(replay(false));

        // 最终重组内容一致，且等于按序到达的结果。
        assertEquals("01234xyevilz", shortFirst.content.toString());
        assertEquals("01234xyevilz", longFirst.content.toString());

        // 命中结果一致：特征 "evil" 在流内偏移 7 处命中一次。
        assertEquals(1, shortFirst.alerts.size());
        assertEquals(1, longFirst.alerts.size());
        assertEquals(shortFirst.alerts, longFirst.alerts);
        assertTrue(shortFirst.alerts.get(0).startsWith("EVIL|7|"),
                "命中偏移应为 7: " + shortFirst.alerts.get(0));

        // 两种顺序都不应产生任何异常。
        assertEquals(List.of(), shortFirst.anomalies);
        assertEquals(List.of(), longFirst.anomalies);
    }
}
