package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.engine.IdsConfig;
import com.github.guoyyit.networkidsjava.ids.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.model.TcpFlags;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import com.github.guoyyit.networkidsjava.ids.source.ListPacketSource;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpAnomalyEvent;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpAnomalyType;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.github.guoyyit.networkidsjava.tests.Packets.C1;
import static com.github.guoyyit.networkidsjava.tests.Packets.C2;
import static com.github.guoyyit.networkidsjava.tests.Packets.P1;
import static com.github.guoyyit.networkidsjava.tests.Packets.P2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EngineIntegrationTest {

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /** Keeps only the newest upsert per deterministic alert id. */
    static final class DedupSink {
        final Map<String, Alert> byId = new LinkedHashMap<>();

        void emit(Alert alert) {
            byId.put(alert.alertId(), alert);
        }

        List<Alert> alerts() {
            return List.copyOf(byId.values());
        }
    }

    private static IdsConfig noPersistence(int maxFlows, long windowMs) {
        return new IdsConfig(maxFlows, 600_000L, 30_000L, 1_048_576L,
                windowMs, 16, 1000L, "target/ignored", false);
    }

    private static void handshake(IdsEngine engine) {
        engine.processPacket(Packets.syn(1, 1000));
        engine.processPacket(Packets.synAck(2, 5000));
        engine.processPacket(Packets.ack(3, C1, P1, C2, P2));
    }

    @Test
    void detectsContentInOrderWithContext() {
        DedupSink sink = new DedupSink();
        try (IdsEngine engine = new IdsEngine(noPersistence(10, 1000), null,
                sink::emit, List.of(new Rule("evil", bytes("secret"))))) {
            handshake(engine);
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "xxsecretyy"));
        }
        List<Alert> alerts = sink.alerts();
        assertEquals(1, alerts.size());
        assertEquals("evil", alerts.get(0).ruleId());
        assertTrue(alerts.get(0).contextHex().contains("736563726574"));
    }

    @Test
    void detectsContentAcrossOutOfOrderPackets() {
        DedupSink inOrderSink = new DedupSink();
        try (IdsEngine engine = new IdsEngine(noPersistence(10, 1000), null,
                inOrderSink::emit, List.of(new Rule("evil", bytes("secret"))))) {
            handshake(engine);
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "sec"));
            engine.processPacket(Packets.data(5, C1, P1, C2, P2, 1004, "ret!"));
        }
        DedupSink reorderedSink = new DedupSink();
        try (IdsEngine engine = new IdsEngine(noPersistence(10, 1000), null,
                reorderedSink::emit, List.of(new Rule("evil", bytes("secret"))))) {
            handshake(engine);
            engine.processPacket(Packets.data(5, C1, P1, C2, P2, 1004, "ret!"));
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "sec"));
        }
        List<Alert> inOrder = inOrderSink.alerts();
        List<Alert> reordered = reorderedSink.alerts();
        assertEquals(1, inOrder.size());
        assertEquals(inOrder.get(0).alertId(), reordered.get(0).alertId());
        assertEquals(inOrder.get(0).contextHex(), reordered.get(0).contextHex());
        assertEquals(inOrder.get(0).firstOffset(), reordered.get(0).firstOffset());
        assertEquals(inOrder.get(0).firstTimestamp(), reordered.get(0).firstTimestamp());
    }

    @Test
    void malformedPacketDoesNotCorruptLaterDetection() {
        DedupSink sink = new DedupSink();
        List<TcpAnomalyEvent> anomalies = new ArrayList<>();
        try (IdsEngine engine = new IdsEngine(noPersistence(10, 1000), null,
                sink::emit, List.of(new Rule("evil", bytes("secret"))))) {
            engine.setAnomalyListener(anomalies::add);
            handshake(engine);
            engine.processPacket(Packets.flags(4, C1, P1, C2, P2,
                    TcpFlags.SYN | TcpFlags.FIN));
            engine.processPacket(Packets.data(5, C1, P1, C2, P2, 1001, "secret"));
        }
        assertEquals(1, anomalies.size());
        assertEquals(TcpAnomalyType.MALFORMED_FLAG_COMBINATION, anomalies.get(0).type());
        assertEquals(1, sink.alerts().size());
    }

    @Test
    void hotRuleAddAndRemoveTakeEffectWithoutRestart() {
        DedupSink sink = new DedupSink();
        try (IdsEngine engine = new IdsEngine(noPersistence(10, 1000), null,
                sink::emit, List.of())) {
            handshake(engine);
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "secret"));
            assertTrue(sink.alerts().isEmpty());

            engine.addRule(new Rule("late", bytes("secret")));
            engine.processPacket(Packets.data(5, C1, P1, C2, P2, 1007, "xxsecret"));
            assertEquals(1, sink.alerts().size());

            assertTrue(engine.removeRule("late"));
            engine.processPacket(Packets.data(6, C1, P1, C2, P2, 1015, "secret"));
            assertEquals(1, sink.alerts().size());
        }
    }

    @Test
    void alertsAggregateByWindowWithCounts() {
        DedupSink sink = new DedupSink();
        try (IdsEngine engine = new IdsEngine(noPersistence(10, 100), null,
                sink::emit, List.of(new Rule("evil", bytes("ab"))))) {
            handshake(engine);
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "ab"));
            engine.processPacket(Packets.data(5, C1, P1, C2, P2, 1003, "ab"));
            engine.processPacket(Packets.data(110, C1, P1, C2, P2, 1005, "ab"));
        }
        List<Alert> alerts = sink.alerts();
        assertEquals(2, alerts.size());
        assertEquals(2, alerts.get(0).hitCount());
        assertEquals(1, alerts.get(1).hitCount());
    }

    @Test
    void capacityForcesOldestEvictionButDeliversInFlightAlerts() {
        DedupSink sink = new DedupSink();
        try (IdsEngine engine = new IdsEngine(noPersistence(1, 1000), null,
                sink::emit, List.of(new Rule("evil", bytes("secret"))))) {
            handshake(engine);
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "secret-pending"));

            Packet otherSyn = new Packet(5, "10.0.0.9", 2000, C2, 81,
                    1, 0, TcpFlags.SYN, new byte[0]);
            engine.processPacket(otherSyn);
            assertEquals(1, engine.activeFlowCount());
        }
        assertEquals(1, sink.alerts().size());
    }

    @Test
    void fixedReplayIsReproducibleAcrossRuns() {
        Rule rule = new Rule("evil", bytes("secret"));
        ListPacketSource source = new ListPacketSource(List.of(
                Packets.syn(1, 1000),
                Packets.synAck(2, 5000),
                Packets.ack(3, C1, P1, C2, P2),
                Packets.data(4, C1, P1, C2, P2, 1001, "xx"),
                Packets.data(5, C1, P1, C2, P2, 1003, "se"),
                Packets.data(6, C1, P1, C2, P2, 1005, "cret!!")));

        List<List<String>> runs = new ArrayList<>();
        for (int run = 0; run < 3; run++) {
            DedupSink sink = new DedupSink();
            try (IdsEngine engine = new IdsEngine(noPersistence(10, 1000), null,
                    sink::emit, List.of(rule))) {
                engine.replay(source);
            }
            runs.add(sink.alerts().stream().map(Alert::toString).toList());
        }
        assertEquals(runs.get(0), runs.get(1));
        assertEquals(runs.get(1), runs.get(2));
        assertEquals(1, runs.get(0).size());
    }
}
