package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.engine.IdsConfig;
import com.github.guoyyit.networkidsjava.ids.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.ids.persistence.CheckpointStore;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.github.guoyyit.networkidsjava.tests.Packets.C1;
import static com.github.guoyyit.networkidsjava.tests.Packets.C2;
import static com.github.guoyyit.networkidsjava.tests.Packets.P1;
import static com.github.guoyyit.networkidsjava.tests.Packets.P2;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CrashRecoveryTest {

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    static final class DedupSink {
        final Map<String, Alert> byId = new LinkedHashMap<>();

        void emit(Alert alert) {
            byId.put(alert.alertId(), alert);
        }

        List<Alert> alerts() {
            return new ArrayList<>(byId.values());
        }
    }

    private IdsConfig config(Path dir) {
        return new IdsConfig(100, 600_000L, 30_000L, 1_048_576L,
                1000L, 16, 1000L, dir.toString(), true);
    }

    @Test
    void restartContinuesFromLastCommitAndRedeliversSnapshotGapAlertsExactlyOnce() throws Exception {
        Path dir = Path.of("target/crash-recovery-test-" + System.nanoTime());
        Rule rule = new Rule("evil", bytes("secret"));

        DedupSink first = new DedupSink();
        CheckpointStore store1 = new CheckpointStore(dir.toString());
        try (IdsEngine engine = new IdsEngine(config(dir), store1, first::emit,
                List.of(rule))) {
            engine.processPacket(Packets.syn(1, 1000));
            engine.processPacket(Packets.synAck(2, 5000));
            engine.processPacket(Packets.ack(3, C1, P1, C2, P2));
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "secret"));
        }
        assertEquals(1, first.alerts().size());

        // Simulate a crash after durable commit but before delivery confirmation.
        java.nio.file.Files.deleteIfExists(dir.resolve("delivery.pos"));

        // Restart: no snapshot exists yet, so the committed but possibly
        // undelivered alerts are re-delivered once; continuing must not repeat.
        DedupSink second = new DedupSink();
        CheckpointStore store2 = new CheckpointStore(dir.toString());
        try (IdsEngine engine = new IdsEngine(config(dir), store2, second::emit,
                List.of(rule))) {
            List<Alert> redelivered = second.alerts();
            assertEquals(1, redelivered.size());
            assertEquals(first.alerts().get(0).alertId(), redelivered.get(0).alertId());
        }
        assertEquals(1, second.alerts().size());

        // Reopening again must not duplicate the redelivery (position advances).
        DedupSink third = new DedupSink();
        try (CheckpointStore store3 = new CheckpointStore(dir.toString());
             IdsEngine engine = new IdsEngine(config(dir), store3, third::emit,
                     List.of(rule))) {
            assertEquals(0, third.alerts().size());
        }
    }

    @Test
    void restartAfterSnapshotDoesNotDuplicateFullyCommittedAlerts() {
        Path dir = Path.of("target/crash-recovery-snap-" + System.nanoTime());
        Rule rule = new Rule("evil", bytes("secret"));
        IdsConfig frequentSnapshot = new IdsConfig(100, 600_000L, 30_000L,
                1_048_576L, 1000L, 16, 2L, dir.toString(), true);

        DedupSink first = new DedupSink();
        try (CheckpointStore store = new CheckpointStore(dir.toString());
             IdsEngine engine = new IdsEngine(frequentSnapshot, store, first::emit,
                     List.of(rule))) {
            engine.processPacket(Packets.syn(1, 1000));
            engine.processPacket(Packets.synAck(2, 5000));
            engine.processPacket(Packets.ack(3, C1, P1, C2, P2));
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "secret"));
        }

        DedupSink second = new DedupSink();
        try (CheckpointStore store = new CheckpointStore(dir.toString());
             IdsEngine engine = new IdsEngine(frequentSnapshot, store, second::emit,
                     List.of(rule))) {
            // commit position 3 is exactly the snapshot position, so it is
            // fully checkpointed and must not be re-delivered (exactly once)
            assertEquals(0, second.alerts().size());
        }
    }

    @Test
    void inFlightOutOfOrderMatchSurvivesSnapshotAndRestart() {
        Path dir = Path.of("target/crash-recovery-ooo-" + System.nanoTime());
        Rule rule = new Rule("evil", bytes("secret"));
        IdsConfig snapEachPacket = new IdsConfig(100, 600_000L, 30_000L,
                1_048_576L, 1000L, 16, 1L, dir.toString(), true);

        CheckpointStore store1 = new CheckpointStore(dir.toString());
        try (IdsEngine engine = new IdsEngine(snapEachPacket, store1, a -> { },
                List.of(rule))) {
            engine.processPacket(Packets.syn(1, 1000));
            engine.processPacket(Packets.synAck(2, 5000));
            engine.processPacket(Packets.ack(3, C1, P1, C2, P2));
            // tail of the pattern first, then crash before the gap fills
            engine.processPacket(Packets.data(5, C1, P1, C2, P2, 1004, "ret"));
        }

        DedupSink after = new DedupSink();
        CheckpointStore store2 = new CheckpointStore(dir.toString());
        try (IdsEngine engine = new IdsEngine(snapEachPacket, store2, after::emit,
                List.of(rule))) {
            engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "sec"));
        }
        assertEquals(1, after.alerts().size());
        assertEquals("evil", after.alerts().get(0).ruleId());
    }

    @Test
    void repeatedRunsProduceIdenticalAlertSequence() {
        Rule rule = new Rule("evil", bytes("ab"));
        Runnable run = () -> { };

        List<List<String>> allRuns = new ArrayList<>();
        for (int attempt = 0; attempt < 2; attempt++) {
            Path dir = Path.of("target/crash-repro-" + System.nanoTime() + "-" + attempt);
            DedupSink sink = new DedupSink();
            CheckpointStore store = new CheckpointStore(dir.toString());
            try (IdsEngine engine = new IdsEngine(config(dir), store, sink::emit,
                    List.of(rule))) {
                engine.processPacket(Packets.syn(1, 1000));
                engine.processPacket(Packets.synAck(2, 5000));
                engine.processPacket(Packets.ack(3, C1, P1, C2, P2));
                engine.processPacket(Packets.data(4, C1, P1, C2, P2, 1001, "ab--ab"));
            }
            allRuns.add(sink.alerts().stream().map(Alert::toString).toList());
        }
        assertEquals(allRuns.get(0), allRuns.get(1));
    }
}
