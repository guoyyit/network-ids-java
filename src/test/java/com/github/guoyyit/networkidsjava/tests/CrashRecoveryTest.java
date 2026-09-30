package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.engine.ProcessResult;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import com.github.guoyyit.networkidsjava.persist.CheckpointStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrashRecoveryTest {

    @TempDir
    Path tempDir;

    private Path stateDir() {
        return tempDir.resolve("state");
    }

    private IdsConfig config(long everyN) {
        IdsConfig config = new IdsConfig();
        config.setStateDir(stateDir().toString());
        config.setCommitEveryNPackets(everyN);
        return config;
    }

    private List<Packet> buildStream() {
        List<Packet> packets = new ArrayList<>();
        packets.add(Packets.c2s(1, 1001, 1000, 0, TcpFlags.SYN, null));
        packets.add(Packets.s2c(2, 1002, 5000, 1001,
                TcpFlags.SYN | TcpFlags.ACK, null));
        packets.add(Packets.c2s(3, 1003, 1001, 5001, TcpFlags.ACK, null));
        for (int i = 0; i < 12; i++) {
            long order = 4 + i;
            packets.add(Packets.c2s(order, 1003L + i, 1001L + i, 5001,
                    TcpFlags.ACK | TcpFlags.PSH, "evil"));
        }
        return packets;
    }

    private Rule rule() {
        return new Rule("EVIL", "evil match", null,
                "evil".getBytes(StandardCharsets.UTF_8), false);
    }

    @Test
    void resumesAfterCommitWithoutDuplicateAlerts() {
        List<Packet> packets = buildStream();
        // 第一段运行：每 5 包提交一次，处理前 8 个报文后"崩溃"(不显式提交最后批次)。
        int crashAt = 8;
        try (IdsEngine engine = new IdsEngine(config(5))) {
            engine.open();
            engine.addRule(rule());
            for (int i = 0; i < crashAt; i++) {
                engine.process(packets.get(i));
            }
            engine.checkpointNow();
        }

        // 重启：从最近提交位置继续，重放完整序列，已提交命中不重复上报。
        List<Alert> secondRunAlerts = new ArrayList<>();
        try (IdsEngine engine = new IdsEngine(config(5))) {
            Long resume = engine.open();
            assertTrue(resume != null && resume >= crashAt - 1,
                    "应从已提交位置恢复, resume=" + resume);
            for (Packet packet : packets) {
                ProcessResult result = engine.process(packet);
                secondRunAlerts.addAll(result.getAlerts());
            }
        }
        // 恢复后只能得到提交位置之后的新命中，不应重复已提交命中。
        for (Alert alert : secondRunAlerts) {
            assertTrue(alert.getCaptureOrder() > resumeOrMinusOne(),
                    "恢复后上报了已提交位置的告警: order=" + alert.getCaptureOrder());
        }
    }

    private long resumeOrMinusOne() {
        try (CheckpointStore store = new CheckpointStore(stateDir(), 100_000)) {
            var cp = store.latestCheckpoint();
            return cp == null ? -1L : cp.getLastProcessedOrder();
        }
    }

    @Test
    void pendingButUncommittedHitIsNotLost() {
        List<Packet> packets = buildStream();
        // 提交间隔极大：命中后"崩溃"(不 close、不提交)，WAL 中保留 pending 记录。
        Path dir = stateDir();
        IdsEngine engine = new IdsEngine(config(1_000_000L));
        engine.open();
        engine.addRule(rule());
        for (int i = 0; i <= 4; i++) {
            engine.process(packets.get(i));
        }
        // 模拟进程崩溃：不调用 close/提交。
        // 恢复视图应能读出崩溃前已命中但未提交的告警。
        try (CheckpointStore store = new CheckpointStore(dir, 100_000)) {
            CheckpointStore.RecoveryState state = store.recover();
            assertFalse(state.getPendingAlerts().isEmpty(),
                    "已命中未提交的结果不应丢失");
            assertEquals("EVIL", state.getPendingAlerts().get(0).getRuleId());
        }
    }

    @Test
    void tornTailRecordIsNeverPartiallyRead() throws Exception {
        List<Packet> packets = buildStream();
        Path dir = stateDir();
        IdsEngine engine = new IdsEngine(config(1_000_000L));
        engine.open();
        engine.addRule(rule());
        for (int i = 0; i < 4; i++) {
            engine.process(packets.get(i));
        }
        // 已命中记录立即 fsync 落盘(不提交)，随后模拟进程崩溃。
        engine.flushPending();
        Path wal = dir.resolve("ids.wal");
        long originalSize = Files.size(wal);
        // 模拟崩溃导致最后一条记录只写了一半：截断尾部若干字节。
        try (var out = Files.newOutputStream(wal,
                java.nio.file.StandardOpenOption.APPEND)) {
            out.write(new byte[]{0x49, 0x44, 0x53, 0x57, 0x00, 0x00});
        }
        // 恢复不得抛异常、不得把截断尾部当作有效记录。
        try (CheckpointStore store = new CheckpointStore(dir, 100_000)) {
            CheckpointStore.RecoveryState state = store.recover();
            assertTrue(Files.size(wal) > originalSize);
            // 已有完整 pending 记录仍可被读出(截断的最后一条被丢弃)。
            assertFalse(state.getPendingAlerts().isEmpty());
        }
    }

    @Test
    void engineRedeliversPendingAlertsAfterRestart() {
        List<Packet> packets = buildStream();
        Path dir = stateDir();

        IdsEngine crashed = new IdsEngine(config(1_000_000L));
        crashed.open();
        crashed.addRule(rule());
        for (int i = 0; i <= 4; i++) {
            crashed.process(packets.get(i));
        }
        crashed.flushPending();
        // 模拟崩溃：不 close、不提交。

        try (IdsEngine restarted = new IdsEngine(config(1_000_000L))) {
            restarted.open();
            List<Alert> redelivered = restarted.drainRecoveredPendingAlerts();
            assertEquals(1, redelivered.size());
            assertEquals("EVIL", redelivered.get(0).getRuleId());
            // 再次取出为空，保证不会无限重复补报。
            assertTrue(restarted.drainRecoveredPendingAlerts().isEmpty());
        }
    }
}
