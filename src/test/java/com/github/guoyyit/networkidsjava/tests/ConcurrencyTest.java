package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.engine.IdsConfig;
import com.github.guoyyit.networkidsjava.ids.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.github.guoyyit.networkidsjava.tests.Packets.C1;
import static com.github.guoyyit.networkidsjava.tests.Packets.C2;
import static com.github.guoyyit.networkidsjava.tests.Packets.P1;
import static com.github.guoyyit.networkidsjava.tests.Packets.P2;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyTest {

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void concurrentRuleChangesDoNotBreakDetection() throws Exception {
        IdsConfig config = new IdsConfig(100, 600_000L, 30_000L, 1_048_576L,
                1000L, 16, 1000L, "target/ignored-concurrency", false);
        Map<String, Alert> alerts = new LinkedHashMap<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();

        ExecutorService pool = Executors.newFixedThreadPool(3);
        CountDownLatch start = new CountDownLatch(1);
        try (IdsEngine engine = new IdsEngine(config, null,
                alert -> {
                    synchronized (alerts) {
                        alerts.put(alert.alertId(), alert);
                    }
                }, List.of(new Rule("stable", bytes("STABLE"))))) {
            engine.processPacket(Packets.syn(1, 1000));
            engine.processPacket(Packets.synAck(2, 5000));
            engine.processPacket(Packets.ack(3, C1, P1, C2, P2));

            pool.submit(() -> guard(failure, start, () -> {
                long seq = 1001;
                for (int i = 0; i < 200; i++) {
                    byte[] payload = ("pre" + i + "STABLEpost").getBytes(StandardCharsets.UTF_8);
                    engine.processPacket(Packets.data(100 + i, C1, P1, C2, P2,
                            seq, payload));
                    seq += payload.length;
                }
            }));
            pool.submit(() -> guard(failure, start, () -> {
                for (int i = 0; i < 100; i++) {
                    engine.addRule(new Rule("dyn" + i, bytes("DY" + i)));
                    if (i % 2 == 0) {
                        engine.removeRule("dyn" + i);
                    }
                }
            }));
            pool.submit(() -> guard(failure, start, () -> {
                for (int i = 0; i < 100; i++) {
                    engine.rules();
                    engine.activeFlowCount();
                }
            }));

            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
            assertNull(failure.get());

            // the stable rule existed the whole time and must fire on every packet
            long stableHits = alerts.values().stream()
                    .filter(a -> a.ruleId().equals("stable"))
                    .mapToLong(Alert::hitCount)
                    .sum();
            assertEquals(200, stableHits);
        }
    }

    private static void guard(AtomicReference<Throwable> failure,
                              CountDownLatch start, Runnable task) {
        try {
            start.await();
            task.run();
        } catch (Throwable t) {
            failure.compareAndSet(null, t);
        }
    }
}
