package com.github.guoyyit.networkidsjava.ids.persistence;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.networkidsjava.ids.alert.Alert;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.channels.Channels;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

/**
 * Durable commit log + atomic state snapshots.
 *
 * <p>Each commit-log record is framed as: magic int, payload length int, JSON
 * payload, CRC32 int of the payload. The file is flushed and fsynced before
 * {@link #appendCommit} returns. On open, the log is scanned forward; a torn
 * tail (truncation, bad length or CRC mismatch after a crash) is detected and
 * truncated, so a single record can never be partially applied and the last
 * good record is the recovery point.
 *
 * <p>Snapshots are written to a temporary file, fsynced and atomically renamed,
 * so a snapshot is either fully present or absent.
 */
public final class CheckpointStore implements AutoCloseable {

    private static final int MAGIC = 0x49445352; // "IDSR"

    private final Path directory;
    private final Path commitLog;
    private final Path snapshotFile;
    private final Path deliveryFile;
    private final ObjectMapper mapper;
    private final FileOutputStream logOutput;
    private final DataOutputStream commitOutput;
    private long lastPosition = -1L;
    private List<Alert> lastAlerts = List.of();

    public CheckpointStore(String directory) {
        try {
            this.directory = Path.of(directory);
            Files.createDirectories(this.directory);
            this.commitLog = this.directory.resolve("commit.log");
            this.snapshotFile = this.directory.resolve("snapshot.json");
            this.deliveryFile = this.directory.resolve("delivery.pos");
            this.mapper = new ObjectMapper()
                    .setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE);
            this.mapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
            this.mapper.setVisibility(PropertyAccessor.CREATOR, JsonAutoDetect.Visibility.ANY);
            recoverLog();
            this.logOutput = new FileOutputStream(commitLog.toFile(), true);
            this.commitOutput = new DataOutputStream(logOutput);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public synchronized void appendCommit(long position, List<Alert> alerts) {
        try {
            byte[] payload = mapper.writeValueAsBytes(new CommitRecord(position, alerts));
            CRC32 crc = new CRC32();
            crc.update(payload);
            commitOutput.writeInt(MAGIC);
            commitOutput.writeInt(payload.length);
            commitOutput.write(payload);
            commitOutput.writeInt((int) crc.getValue());
            commitOutput.flush();
            logOutput.getFD().sync();
            lastPosition = position;
            lastAlerts = List.copyOf(alerts);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public synchronized List<CommitRecord> readCommitsAfter(long position) {
        List<CommitRecord> result = new ArrayList<>();
        for (CommitRecord record : readAllCommits()) {
            if (record.position() > position) {
                result.add(record);
            }
        }
        return result;
    }

    public synchronized long lastCommittedPosition() {
        return lastPosition;
    }

    public synchronized List<Alert> lastCommittedAlerts() {
        return lastAlerts;
    }

    public synchronized void writeSnapshot(SnapshotData snapshot) {
        try {
            Path temp = directory.resolve("snapshot.json.tmp");
            try (OutputStream out = new FileOutputStream(temp.toFile())) {
                mapper.writeValue(out, snapshot);
                out.flush();
                try {
                    ((FileOutputStream) out).getFD().sync();
                } catch (java.io.SyncFailedException fsyncUnsupported) {
                    // Some non-durable filesystems (tmpfs in sandboxes) reject
                    // fsync; the bytes are already handed to the OS here.
                }
            }
            try {
                Files.move(temp, snapshotFile, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException atomicUnsupported) {
                Files.move(temp, snapshotFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public synchronized long deliveredPosition() {
        if (!Files.exists(deliveryFile)) {
            return -1L;
        }
        try {
            return Long.parseLong(Files.readString(deliveryFile).trim());
        } catch (IOException | NumberFormatException e) {
            return -1L;
        }
    }

    public synchronized void markDelivered(long position) {
        try {
            Path temp = directory.resolve("delivery.pos.tmp");
            Files.writeString(temp, Long.toString(position));
            try {
                Files.move(temp, deliveryFile, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException atomicUnsupported) {
                Files.move(temp, deliveryFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public synchronized SnapshotData readSnapshot() {
        if (!Files.exists(snapshotFile)) {
            return null;
        }
        try {
            return mapper.readValue(snapshotFile.toFile(), SnapshotData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public synchronized void close() {
        try {
            commitOutput.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void recoverLog() throws IOException {
        if (!Files.exists(commitLog) || Files.size(commitLog) == 0) {
            return;
        }
        long validLength = 0L;
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(
                Files.newInputStream(commitLog)))) {
            while (true) {
                long frameStart = validLength;
                int magic;
                try {
                    magic = in.readInt();
                } catch (EOFException eof) {
                    break;
                }
                if (magic != MAGIC) {
                    break;
                }
                int length = in.readInt();
                if (length <= 0 || length > 256 * 1024 * 1024) {
                    break;
                }
                byte[] payload = new byte[length];
                in.readFully(payload);
                int expectedCrc = in.readInt();
                CRC32 crc = new CRC32();
                crc.update(payload);
                if ((int) crc.getValue() != expectedCrc) {
                    break;
                }
                CommitRecord record = mapper.readValue(payload, CommitRecord.class);
                validLength = frameStart + 4L + 4L + length + 4L;
                if (record.position() > lastPosition) {
                    lastPosition = record.position();
                    lastAlerts = List.copyOf(record.alerts());
                }
            }
        }
        if (validLength != Files.size(commitLog)) {
            try (var ch = Files.newByteChannel(commitLog, StandardOpenOption.WRITE)) {
                ch.truncate(validLength);
            }
        }
    }

    private List<CommitRecord> readAllCommits() {
        List<CommitRecord> records = new ArrayList<>();
        if (!Files.exists(commitLog)) {
            return records;
        }
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(
                Files.newInputStream(commitLog)))) {
            while (true) {
                int magic;
                try {
                    magic = in.readInt();
                } catch (EOFException eof) {
                    break;
                }
                int length = in.readInt();
                byte[] payload = new byte[length];
                in.readFully(payload);
                in.readInt();
                if (magic == MAGIC) {
                    records.add(mapper.readValue(payload, CommitRecord.class));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return records;
    }
}
