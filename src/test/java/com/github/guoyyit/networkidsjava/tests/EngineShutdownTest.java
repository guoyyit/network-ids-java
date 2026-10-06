package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 正常关闭路径上的在途命中处理。 */
class EngineShutdownTest {

    @TempDir
    Path tempDir;

    private IdsConfig config() {
        IdsConfig config = new IdsConfig();
        config.setStateDir(tempDir.resolve("ids-state").toString());
        config.setCommitEveryNPackets(10_000L);
        return config;
    }

    private Rule evilRule() {
        return new Rule("EVIL", "evil match", null,
                "evil".getBytes(StandardCharsets.UTF_8), false);
    }

    /** 握手 + 一个含特征的报文(命中进入聚合窗口但窗口未关闭)。 */
    private List<Packet> handshakeWithHit() {
        List<Packet> packets = new ArrayList<>();
        packets.add(Packets.c2s(1, 1001, 1000, 0, TcpFlags.SYN, null));
        packets.add(Packets.s2c(2, 1002, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null));
        packets.add(Packets.c2s(3, 1003, 1001, 5001, TcpFlags.ACK, null));
        packets.add(Packets.c2s(4, 1004, 1001, 5001,
                TcpFlags.ACK | TcpFlags.PSH, "xxevilxx"));
        return packets;
    }

    @Test
    void closeFlushesInFlightAggregatedAlerts() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(evilRule());
        for (Packet p : handshakeWithHit()) {
            engine.process(p);
        }
        // 命中仍在聚合窗口内(未刷出)；正常关闭不得静默丢弃。
        engine.close();

        List<AggregatedAlert> finalAlerts = engine.drainFinalAggregatedAlerts();
        assertEquals(1, finalAlerts.size(), "关闭时刷出的在途命中必须可观察");
        assertEquals("EVIL", finalAlerts.get(0).getRuleId());
        assertEquals(1L, finalAlerts.get(0).getHitCount());
        assertTrue(finalAlerts.get(0).getFirstContext().contains("evil"));
        // 再次取出为空，不会重复返回。
        assertTrue(engine.drainFinalAggregatedAlerts().isEmpty());
    }

    @Test
    void closeIsIdempotentAndDoesNotDoubleFlush() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(evilRule());
        for (Packet p : handshakeWithHit()) {
            engine.process(p);
        }
        engine.close();
        engine.close();
        assertEquals(1, engine.drainFinalAggregatedAlerts().size());
    }

    @Test
    void processAfterCloseIsRejectedObservably() {
        IdsEngine engine = new IdsEngine(config());
        engine.open();
        engine.addRule(evilRule());
        engine.close();
        // 关闭后再处理必须显式失败，而不是静默丢弃命中。
        assertThrows(IllegalStateException.class,
                () -> engine.process(Packets.c2s(1, 1001, 1000, 0, TcpFlags.SYN, null)));
    }
}
