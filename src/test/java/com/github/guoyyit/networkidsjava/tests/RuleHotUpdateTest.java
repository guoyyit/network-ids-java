package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.Alert;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleHotUpdateTest {

    @TempDir
    Path tempDir;

    private IdsConfig config() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("state").toString());
        config.setCommitEveryNPackets(100_000L);
        return config;
    }

    private Packet data(long order, String body) {
        return Packets.c2s(order, 1000L + order, 1001 + bodyOffset(order),
                5001, TcpFlags.ACK | TcpFlags.PSH, body);
    }

    private long bodyOffset(long order) {
        // 每个数据段 3 字节，互不重叠。
        return (order - 4) * 3;
    }

    @Test
    void addedRuleTakesEffectImmediately() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            feedHandshake(engine);

            ProcessResult before = engine.process(data(4, "abc"));
            assertTrue(before.getAlerts().isEmpty());

            engine.addRule(RuleParser.parse("NEW: content:xyz; message:xyz found"));
            ProcessResult after = engine.process(data(5, "xyz"));
            assertEquals(1, after.getAlerts().size());
            assertEquals("NEW", after.getAlerts().get(0).getRuleId());
        }
    }

    @Test
    void removedRuleStopsMatching() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            engine.addRule(new Rule("R", "m", null, "abc".getBytes(), false));
            feedHandshake(engine);
            assertEquals(1, engine.process(data(4, "abc")).getAlerts().size());

            assertTrue(engine.removeRule("R"));
            ProcessResult later = engine.process(data(5, "abc"));
            assertTrue(later.getAlerts().isEmpty());
        }
    }

    @Test
    void updateRulesDoesNotInterruptDetection() {
        try (IdsEngine engine = new IdsEngine(config())) {
            engine.open();
            feedHandshake(engine);
            engine.addRule(new Rule("A", "m", null, "abc".getBytes(), false));
            // 热更新若干次，期间持续检测不中断、不漏检。
            assertEquals(1, engine.process(data(4, "abc")).getAlerts().size());
            engine.addRule(new Rule("B", "m", null, "def".getBytes(), false));
            ProcessResult both = engine.process(data(5, "def"));
            assertEquals(1, both.getAlerts().size());
            engine.removeRule("A");
            ProcessResult noA = engine.process(data(6, "abc"));
            assertTrue(noA.getAlerts().isEmpty());
            assertFalse(engine.getRuleSet().snapshot().isEmpty());
        }
    }

    private void feedHandshake(IdsEngine engine) {
        engine.process(Packets.c2s(1, 1001, 1000, 0, TcpFlags.SYN, null));
        engine.process(Packets.s2c(2, 1002, 5000, 1001,
                TcpFlags.SYN | TcpFlags.ACK, null));
        engine.process(Packets.c2s(3, 1003, 1001, 5001, TcpFlags.ACK, null));
    }
}
