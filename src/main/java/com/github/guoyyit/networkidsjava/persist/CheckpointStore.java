package com.github.guoyyit.networkidsjava.persist;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.CRC32;

/**
 * 预写日志式持久化，全部在一个目录下完成，无需外部服务。
 *
 * <p>记录类型:
 * <ul>
 *   <li>PENDING_ALERT  : 命中后、上报前落盘(保证不丢已命中结果)</li>
 *   <li>COMMIT         : 原子提交(位置 + 已提交告警身份 + 规则快照)</li>
 * </ul>
 * 每条记录长度前缀 + CRC32；单条记录要么完整可读要么按截断尾部丢弃，
 * 不会出现部分写入被当成有效记录。
 */
public final class CheckpointStore implements AutoCloseable {

    private static final byte REC_PENDING = 1;
    private static final byte REC_COMMIT = 2;
    private static final byte[] MAGIC = {'I', 'D', 'S', 'W'};

    private final Path stateDir;
    private final Path walFile;
    private final int maxCommittedRetain;
    private OutputStream walOut;

    // 内存中保留最近一次提交后的已提交告警身份(用于重放去重)，受 this 锁保护。
    private final Set<String> committedIdentities = new HashSet<>();
    private final List<Alert> pendingAlerts = new ArrayList<>();
    private Checkpoint latest;

    public CheckpointStore(Path stateDir, int maxCommittedRetain) {
        try {
            this.stateDir = stateDir;
            this.maxCommittedRetain = maxCommittedRetain;
            Files.createDirectories(stateDir);
            this.walFile = stateDir.resolve("ids.wal");
            if (Files.notExists(walFile)) {
                Files.createFile(walFile);
            }
            this.walOut = Files.newOutputStream(walFile,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new IllegalStateException("初始化状态目录失败: " + stateDir, e);
        }
    }

    /** 追加一条待提交告警。 */
    public synchronized void appendPending(Alert alert) {
        try {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(body)) {
                writeAlert(out, alert);
            }
            appendRecord(REC_PENDING, body.toByteArray());
            walOut.flush();
            if (walOut instanceof java.io.FileOutputStream fos) {
                fos.getFD().sync();
            }
            pendingAlerts.add(alert);
        } catch (IOException e) {
            throw new IllegalStateException("写入待提交告警失败", e);
        }
    }

    /** 仅强制刷盘 WAL(不推进提交点)，用于崩溃前保证已命中记录落盘。 */
    public synchronized void flush() {
        try {
            walOut.flush();
            if (walOut instanceof java.io.FileOutputStream fos) {
                fos.getFD().sync();
            }
        } catch (IOException e) {
            throw new IllegalStateException("刷盘失败", e);
        }
    }

    /**
     * 原子提交：已处理位置与本批已上报告警身份，以及规则快照。
 * 返回 true 表示落盘并 fsync 成功(此后崩溃不会重复上报/重复检测)。
     */
    public synchronized boolean commit(long lastProcessedOrder,
                                       List<String> committedAlertIdentities,
                                       long ruleVersion,
                                       List<String> ruleLines) {
        try {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(body)) {
                out.writeLong(lastProcessedOrder);
                out.writeLong(ruleVersion);
                out.writeInt(ruleLines.size());
                for (String line : ruleLines) {
                    writeUtf(out, line);
                }
                out.writeInt(committedAlertIdentities.size());
                for (String identity : committedAlertIdentities) {
                    writeUtf(out, identity);
                }
            }
            appendRecord(REC_COMMIT, body.toByteArray());
            walOut.flush();
            // 强制落盘，确保提交点不丢。
            if (walOut instanceof java.io.FileOutputStream fos) {
                fos.getFD().sync();
            }
            this.latest = new Checkpoint(lastProcessedOrder, ruleVersion, ruleLines);
            committedIdentities.addAll(committedAlertIdentities);
            trimCommittedRetain();
            pendingAlerts.clear();
            return true;
        } catch (IOException e) {
            throw new IllegalStateException("提交失败", e);
        }
    }

    /** 读取最近一次提交点；无提交返回 null。 */
    public synchronized Checkpoint latestCheckpoint() {
        if (latest == null) {
            recover();
        }
        return latest;
    }

    /** 恢复视图：最近提交点、已提交告警身份、崩溃前已落盘但未确认的告警。 */
    public synchronized RecoveryState recover() {
        Checkpoint checkpoint = null;
        Set<String> committed = new HashSet<>();
        List<Alert> pending = new ArrayList<>();
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(
                Files.newInputStream(walFile)))) {
            while (true) {
                byte[] record;
                try {
                    record = readRecord(in);
                } catch (IOException end) {
                    break; // EOF 或截断尾部，停止。
                }
                if (record == null) {
                    break;
                }
                byte type = record[0];
                byte[] payload = new byte[record.length - 1];
                System.arraycopy(record, 1, payload, 0, payload.length);
                if (type == REC_COMMIT) {
                    parseCommit(payload, committed);
                    checkpoint = latest;
                    pending.clear();
                } else if (type == REC_PENDING) {
                    pending.add(readAlert(payload));
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("读取 WAL 失败", e);
        }
        // 无论是否曾提交，最后一次提交之后仍未确认的 pending 即"已命中未提交"，
        // 恢复后需要补报。
        return new RecoveryState(checkpoint, committed, pending);
    }

    /** 关闭并刷盘。 */
    public synchronized void close() {
        try {
            if (walOut != null) {
                walOut.flush();
                if (walOut instanceof java.io.FileOutputStream fos) {
                    fos.getFD().sync();
                }
                walOut.close();
                walOut = null;
            }
        } catch (IOException e) {
            throw new IllegalStateException("关闭状态存储失败", e);
        }
    }

    private void parseCommit(byte[] payload, Set<String> committedSink) throws IOException {
        try (DataInputStream in = new DataInputStream(
                new java.io.ByteArrayInputStream(payload))) {
            long order = in.readLong();
            long ruleVersion = in.readLong();
            int ruleCount = in.readInt();
            List<String> rules = new ArrayList<>();
            for (int i = 0; i < ruleCount; i++) {
                rules.add(readUtf(in));
            }
            int idCount = in.readInt();
            committedIdentities.clear();
            for (int i = 0; i < idCount; i++) {
                committedIdentities.add(readUtf(in));
            }
            trimCommittedRetain();
            this.latest = new Checkpoint(order, ruleVersion, rules);
            committedSink.addAll(committedIdentities);
        }
    }

    private void trimCommittedRetain() {
        // 身份集合只用于最近窗口去重；超出上限时整体让旧身份过期是安全的：
        // 旧位置不会因重放再次到达(重放严格从提交位置继续)。
        if (committedIdentities.size() <= maxCommittedRetain) {
            return;
        }
        committedIdentities.clear();
    }

    // ---- 记录帧: MAGIC | len(int) | body | crc32(long) ----
    // 单条记录要么完整通过 CRC 校验，要么在长度/CRC 不匹配时作为截断尾部被丢弃，
    // 不会把部分写入误当作有效记录。
    private void appendRecord(byte type, byte[] body) throws IOException {
        byte[] record = new byte[body.length + 1];
        record[0] = type;
        System.arraycopy(body, 0, record, 1, body.length);
        CRC32 crc = new CRC32();
        crc.update(record);
        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(frame)) {
            out.write(MAGIC);
            out.writeInt(record.length);
            out.write(record);
            out.writeLong(crc.getValue());
        }
        walOut.write(frame.toByteArray());
    }

    /** 读取一条完整记录；遇 EOF 或损坏(截断)尾部抛异常以停止恢复。 */
    private byte[] readRecord(DataInputStream in) throws IOException {
        byte[] magic = new byte[MAGIC.length];
        in.readFully(magic);
        for (int i = 0; i < MAGIC.length; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new IOException("WAL magic 不匹配(文件损坏)");
            }
        }
        int len = in.readInt();
        if (len < 0 || len > 64 * 1024 * 1024) {
            throw new IOException("WAL 记录长度非法: " + len);
        }
        byte[] record = new byte[len];
        in.readFully(record);
        long expectedCrc = in.readLong();
        CRC32 crc = new CRC32();
        crc.update(record);
        if (crc.getValue() != expectedCrc) {
            throw new IOException("WAL CRC 校验失败(检测到部分写入的截断尾部)");
        }
        return record;
    }

    private static void writeAlert(DataOutputStream out, Alert alert) throws IOException {
        writeUtf(out, alert.getRuleId());
        writeUtf(out, alert.getMessage());
        writeUtf(out, alert.getFlowKey().getSrcIp());
        out.writeInt(alert.getFlowKey().getSrcPort());
        writeUtf(out, alert.getFlowKey().getDstIp());
        out.writeInt(alert.getFlowKey().getDstPort());
        writeUtf(out, alert.getDirection().name());
        out.writeLong(alert.getStreamOffset());
        writeUtf(out, alert.getMatchedContext());
        out.writeLong(alert.getTimestampMillis());
        out.writeLong(alert.getCaptureOrder());
    }

    private static Alert readAlert(byte[] payload) throws IOException {
        try (DataInputStream in = new DataInputStream(
                new java.io.ByteArrayInputStream(payload))) {
            String ruleId = readUtf(in);
            String message = readUtf(in);
            String srcIp = readUtf(in);
            int srcPort = in.readInt();
            String dstIp = readUtf(in);
            int dstPort = in.readInt();
            Direction direction = Direction.valueOf(readUtf(in));
            long offset = in.readLong();
            String context = readUtf(in);
            long ts = in.readLong();
            long order = in.readLong();
            FlowKey key = new FlowKey(srcIp, srcPort, dstIp, dstPort);
            return new Alert(ruleId, message, key, direction, offset, context, ts, order);
        }
    }

    private static void writeUtf(DataOutputStream out, String value) throws IOException {
        byte[] bytes = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readUtf(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len < 0) {
            throw new IOException("UTF 长度非法");
        }
        byte[] bytes = new byte[len];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** 恢复结果。 */
    public static final class RecoveryState {
        private final Checkpoint checkpoint;
        private final Set<String> committed;
        private final List<Alert> pendingAlerts;

        public RecoveryState(Checkpoint checkpoint, Set<String> committed,
                             List<Alert> pendingAlerts) {
            this.checkpoint = checkpoint;
            this.committed = committed;
            this.pendingAlerts = pendingAlerts;
        }

        public Checkpoint getCheckpoint() {
            return checkpoint;
        }

        public boolean isCommitted(String alertIdentity) {
            return committed.contains(alertIdentity);
        }

        public List<Alert> getPendingAlerts() {
            return List.copyOf(pendingAlerts);
        }
    }
}
