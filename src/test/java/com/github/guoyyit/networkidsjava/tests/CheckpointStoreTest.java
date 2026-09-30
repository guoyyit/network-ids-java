package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.persistence.CheckpointStore;
import com.github.guoyyit.networkidsjava.ids.persistence.CommitRecord;
import com.github.guoyyit.networkidsjava.ids.persistence.FlowSnapshot;
import com.github.guoyyit.networkidsjava.ids.persistence.SnapshotData;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class CheckpointStoreTest {

    private static Alert alert(long first, long count) {
        return new Alert("id" + first, "conn#1", "r", first, first + 10,
                count, "INITIATOR", 0, "abcd");
    }

    @TempDir
    Path tempDir;

    @Test
    void commitsAreWrittenAndReadBack() {
        String dir = tempDir.resolve("a").toString();
        try (CheckpointStore store = new CheckpointStore(dir)) {
            store.appendCommit(0, List.of(alert(0, 1)));
            store.appendCommit(1, List.of());
            store.appendCommit(2, List.of(alert(5, 3)));
            assertEquals(2, store.lastCommittedPosition());
        }
        try (CheckpointStore reopened = new CheckpointStore(dir)) {
            assertEquals(2, reopened.lastCommittedPosition());
            List<CommitRecord> afterOne = reopened.readCommitsAfter(0);
            assertEquals(2, afterOne.size());
            assertEquals(3, reopened.lastCommittedAlerts().get(0).hitCount());
        }
    }

    @Test
    void tornTailIsDetectedAndTruncated() throws Exception {
        String dir = tempDir.resolve("b").toString();
        try (CheckpointStore store = new CheckpointStore(dir)) {
            store.appendCommit(10, List.of(alert(0, 1)));
        }
        Path log = Path.of(dir, "commit.log");
        long goodLength = log.toFile().length();
        try (RandomAccessFile raf = new RandomAccessFile(log.toFile(), "rw")) {
            raf.seek(goodLength);
            raf.write(new byte[]{0, 0, 0, 0x49, 1, 2, 3});
        }
        try (CheckpointStore reopened = new CheckpointStore(dir)) {
            assertEquals(10, reopened.lastCommittedPosition());
            assertEquals(1, reopened.readCommitsAfter(-1).size());
        }
        assertEquals(goodLength, log.toFile().length());
    }

    @Test
    void corruptedPayloadCrcRejectsPartialRecord() throws Exception {
        String dir = tempDir.resolve("c").toString();
        try (CheckpointStore store = new CheckpointStore(dir)) {
            store.appendCommit(10, List.of(alert(0, 1)));
            store.appendCommit(11, List.of(alert(9, 1)));
        }
        Path log = Path.of(dir, "commit.log");
        try (RandomAccessFile raf = new RandomAccessFile(log.toFile(), "rw")) {
            long length = raf.length();
            raf.seek(length - 8);
            raf.write(new byte[]{(byte) 0xFF, (byte) 0xFF});
        }
        try (CheckpointStore reopened = new CheckpointStore(dir)) {
            assertEquals(10, reopened.lastCommittedPosition());
        }
    }

    @Test
    void snapshotsAreAtomicAndRestorable() {
        String dir = tempDir.resolve("d").toString();
        FlowSnapshot flow = new FlowSnapshot();
        flow.flowKey = "a:1<->b:2";
        flow.incarnation = 1;
        flow.tcpState = "ESTABLISHED";
        flow.lastSeen = 42;
        flow.initiatorIp = "a";
        flow.initiatorPort = 1;
        flow.responderIp = "b";
        flow.responderPort = 2;
        SnapshotData snapshot = new SnapshotData(7,
                List.of(new Rule("r", "xx".getBytes(StandardCharsets.UTF_8))),
                List.of(flow));
        try (CheckpointStore store = new CheckpointStore(dir)) {
            assertNull(store.readSnapshot());
            store.writeSnapshot(snapshot);
        }
        try (CheckpointStore reopened = new CheckpointStore(dir)) {
            SnapshotData read = reopened.readSnapshot();
            assertNotNull(read);
            assertEquals(7, read.position());
            assertEquals(1, read.rules().size());
            assertEquals("ESTABLISHED", read.flows().get(0).tcpState);
        }
    }
}
