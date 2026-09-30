package com.github.guoyyit.networkidsjava.engine;

import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.alert.AlertAggregator;
import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.Rule;
import com.github.guoyyit.networkidsjava.detect.RuleParser;
import com.github.guoyyit.networkidsjava.detect.RuleSet;
import com.github.guoyyit.networkidsjava.model.AnomalyEvent;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.persist.Checkpoint;
import com.github.guoyyit.networkidsjava.persist.CheckpointStore;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 入侵检测引擎门面：组装流表、检测、聚合与持久化，提供可复现的处理入口。
 */
public final class IdsEngine implements AutoCloseable {
    private final IdsConfig config;
    private final RuleSet ruleSet;
    private final CheckpointStore store;
    private final FlowTable flowTable;
    private final AlertAggregator aggregator;
    private final List<String> pendingCommitIdentities = new ArrayList<>();
    private final Set<Long> inFlightOrders = new HashSet<>();
    private long processedSinceCommit;
    private long lastProcessedOrder;
    private long resumeAfterOrder = Long.MIN_VALUE;
    private long contiguousOrder;
    private List<Alert> recoveredPending = new ArrayList<>();
    private CheckpointStore.RecoveryState recoveryState;
    private boolean opened;

    public IdsEngine(IdsConfig config) {
        this.config = config;
        this.ruleSet = new RuleSet();
        this.store = new CheckpointStore(Path.of(config.getStateDir()),
                config.getMaxCommittedRetain());
        this.flowTable = new FlowTable(config);
        this.aggregator = new AlertAggregator(config.getAlertWindowMillis());
    }

    /** 从持久化目录恢复(已提交位置/规则)，未恢复过时返回 null。 */
    public synchronized Long open() {
        recoveryState = store.recover();
        opened = true;
        recoveredPending = new ArrayList<>(recoveryState.getPendingAlerts());
        Checkpoint checkpoint = recoveryState.getCheckpoint();
        if (checkpoint == null) {
            lastProcessedOrder = -1L;
            return null;
        }
        ruleSet.replaceAll(RuleParser.parseAll(checkpoint.getRuleLines()));
        lastProcessedOrder = checkpoint.getLastProcessedOrder();
        resumeAfterOrder = checkpoint.getLastProcessedOrder();
        contiguousOrder = checkpoint.getLastProcessedOrder();
        return lastProcessedOrder;
    }

    /**
     * 取出崩溃前已命中但未提交的告警(恢复后补报用)。取出即清空；
     * 这些告警直接来自 WAL，不会因重放而重复产生。
     */
    public synchronized List<Alert> drainRecoveredPendingAlerts() {
        List<Alert> snapshot = List.copyOf(recoveredPending);
        recoveredPending.clear();
        return snapshot;
    }

    /** 处理单个报文，返回告警(已聚合)与异常。 */
    public synchronized ProcessResult process(Packet packet) {
        if (!opened) {
            open();
        }
        ProcessResult result = new ProcessResult();
        // 重放保护：仅在从提交点恢复后跳过已提交序号(<=提交水位)。
        // 正常乱序输入中，即使报文顺序与序号不一致也不会被跳过——
        // 只有恢复重放(同一报文序列从头喂入)才会命中该水位。
        long order = packet.getCaptureOrder();
        if (order <= resumeAfterOrder) {
            return result;
        }
        inFlightOrders.add(order);

        // 事件时间驱动的老化回收(可复现，不依赖墙钟)。
        for (TcpFlow evicted : flowTable.tick(packet.getTimestampMillis())) {
            evicted.syncRules(ruleSet);
        }

        FlowKey key = FlowKey.of(packet.getSrcIp(), packet.getSrcPort(),
                packet.getDstIp(), packet.getDstPort());
        FlowTable.AcquireResult acquired =
                flowTable.acquire(key, packet.getTimestampMillis());
        result.getAnomalies().addAll(acquired.getAnomalies());
        TcpFlow flow = acquired.getFlow();
        if (flow == null) {
            // 流表满且不可回收：报文被安全丢弃，既有状态不受影响。
            return result;
        }

        FlowResult flowResult = flow.handle(packet, ruleSet);
        result.getAnomalies().addAll(flowResult.getAnomalies());

        for (Alert alert : flowResult.getAlerts()) {
            // 已提交过的相同命中不重复上报(崩溃重放去重)。
            if (recoveryState != null && recoveryState.isCommitted(alert.identity())) {
                continue;
            }
            store.appendPending(alert);
            result.getAlerts().add(alert);
            result.getAggregatedAlerts().addAll(aggregator.accept(alert));
            pendingCommitIdentities.add(alert.identity());
        }

        lastProcessedOrder = Math.max(lastProcessedOrder, packet.getCaptureOrder());
        processedSinceCommit++;
        if (processedSinceCommit >= config.getCommitEveryNPackets()) {
            maybeCommit();
        }
        return result;
    }

    /** 固定输入的便捷入口：按序处理整个报文列表。 */
    public synchronized List<AggregatedAlert> runReplay(List<Packet> packets) {
        List<AggregatedAlert> output = new ArrayList<>();
        for (Packet packet : packets) {
            ProcessResult result = process(packet);
            output.addAll(result.getAggregatedAlerts());
        }
        output.addAll(aggregator.flushAll());
        return output;
    }

    public synchronized void addRule(Rule rule) {
        ruleSet.addOrUpdate(rule);
    }

    public synchronized boolean removeRule(String ruleId) {
        return ruleSet.remove(ruleId);
    }

    public synchronized void replaceRules(List<Rule> rules) {
        ruleSet.replaceAll(rules);
    }

    public RuleSet getRuleSet() {
        return ruleSet;
    }

    /** 强制提交当前位置与待确认告警。 */
    public synchronized void checkpointNow() {
        maybeCommit();
    }

    /** 仅把已命中未提交告警刷盘(不推进提交位置)。 */
    public synchronized void flushPending() {
        store.flush();
    }

    @Override
    public synchronized void close() {
        List<AggregatedAlert> tail = aggregator.flushAll();
        if (!tail.isEmpty()) {
            // 关闭时刷出的聚合告警仅做最终提交。
        }
        maybeCommit();
        store.close();
    }

    private void commit() {
        commitAt(contiguousOrder);
    }

    /** 仅当已处理序号连续到 contiguousOrder 时提交，避免乱序下漏处理。 */
    private void maybeCommit() {
        while (inFlightOrders.remove(contiguousOrder + 1)) {
            contiguousOrder++;
        }
        if (processedSinceCommit > 0) {
            commitAt(contiguousOrder);
        }
    }

    private void commitAt(long order) {
        store.commit(order, pendingCommitIdentities,
                ruleSet.getVersion(), ruleSet.toLines());
        pendingCommitIdentities.clear();
        processedSinceCommit = 0;
    }
}
