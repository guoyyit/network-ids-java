package com.github.guoyyit.networkidsjava.ids.engine;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.alert.AlertAggregator;
import com.github.guoyyit.networkidsjava.ids.alert.AlertSink;
import com.github.guoyyit.networkidsjava.ids.detect.MatchHit;
import com.github.guoyyit.networkidsjava.ids.detect.StreamingMatcher;
import com.github.guoyyit.networkidsjava.ids.flow.FlowTable;
import com.github.guoyyit.networkidsjava.ids.flow.TcpFlow;
import com.github.guoyyit.networkidsjava.ids.model.FlowKey;
import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.persistence.CheckpointStore;
import com.github.guoyyit.networkidsjava.ids.persistence.FlowSnapshot;
import com.github.guoyyit.networkidsjava.ids.persistence.SnapshotData;
import com.github.guoyyit.networkidsjava.ids.reassembly.ReassembledChunk;
import com.github.guoyyit.networkidsjava.ids.reassembly.StreamReassembler;
import com.github.guoyyit.networkidsjava.ids.rule.ConcurrentRuleSet;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import com.github.guoyyit.networkidsjava.ids.source.PacketSource;
import com.github.guoyyit.networkidsjava.ids.tcp.Direction;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpAnomalyEvent;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpAnomalyType;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Engine facade: TCP state tracking, stream reassembly, content matching,
 * alert aggregation, ageing/eviction and crash recovery.
 *
 * <p>All detection is serialized under one lock. Rule updates use copy-on-write
 * snapshots and never interrupt an in-flight pass. Every processed packet ends
 * in a durable commit (position + emitted alerts); alerts are only delivered to
 * the {@link AlertSink} from a committed record, which gives exactly-once
 * delivery across crashes.
 */
public final class IdsEngine implements AutoCloseable {

    private final IdsConfig config;
    private final CheckpointStore store;
    private final AlertSink sink;
    private final ConcurrentRuleSet ruleSet;
    private final FlowTable flowTable;
    private final AlertAggregator aggregator;
    private final Object lock = new Object();
    private final Map<TcpFlow, EnumMap<Direction, StreamingMatcher>> matchers = new HashMap<>();

    private long lastCommittedPosition;
    private long packetsSinceSnapshot;
    private long maxObservedTimestamp;
    private Consumer<TcpAnomalyEvent> anomalyListener;

    public IdsEngine(IdsConfig config, CheckpointStore store, AlertSink sink) {
        this(config, store, sink, null);
    }

    public IdsEngine(IdsConfig config, CheckpointStore store, AlertSink sink,
                     List<Rule> initialRules) {
        this.config = config;
        this.store = store;
        this.sink = sink;
        this.ruleSet = new ConcurrentRuleSet(initialRules == null ? List.of() : initialRules);
        this.flowTable = new FlowTable(config.maxFlows(), config.idleTimeoutMs(),
                config.closedTimeoutMs());
        this.aggregator = new AlertAggregator(config.aggregationWindowMs());
        this.lastCommittedPosition = config.persistenceEnabled() && store != null
                ? store.lastCommittedPosition() : -1L;
        recover();
    }

    public long lastCommittedPosition() {
        synchronized (lock) {
            return lastCommittedPosition;
        }
    }

    /**
     * Process one packet synchronously and return the alerts that became
     * durable and were delivered for it (may include aggregation boundary
     * alerts from other keys).
     */
    public List<Alert> processPacket(Packet packet) {
        synchronized (lock) {
            List<Alert> emitted = new ArrayList<>();
            long position = packet.position() >= 0
                    ? packet.position() : lastCommittedPosition + 1;
            Packet effective = packet.position() >= 0 ? packet : packet.withPosition(position);

            flowTable.evictExpired(effective.timestamp(), flow -> flushFlow(flow, emitted));

            FlowKey key = FlowKey.of(effective);
            TcpFlow flow;
            if (flowTable.get(key) == null && flowTable.size() >= flowTable.capacity()) {
                flowTable.evictOldest(effective.timestamp(), f -> flushFlow(f, emitted));
            }
            flow = flowTable.getOrCreate(key, effective.timestamp(),
                    config.maxBufferedBytesPerDirection());

            TcpAnomalyEvent anomaly = flow.handlePacket(effective);
            if (anomaly != null) {
                notifyAnomaly(anomaly);
                commit(effective.position(), emitted);
                return List.copyOf(emitted);
            }

            for (Direction direction : flow.readyDirections()) {
                StreamReassembler reassembler = flow.reassembler(direction);
                List<ReassembledChunk> chunks = reassembler.pollReady();
                if (chunks.isEmpty()) {
                    continue;
                }
                StreamingMatcher matcher = matcherFor(flow, direction);
                for (ReassembledChunk chunk : chunks) {
                    for (MatchHit hit : matcher.feed(chunk.startSeq(), chunk.data())) {
                        MatchHit directed = new MatchHit(hit.rule(), direction,
                                hit.offset(), hit.context());
                        emitted.addAll(aggregator.record(directed, flow.connectionId(),
                                chunk.completionTimestamp()));
                    }
                }
            }

            commit(effective.position(), emitted);
            return List.copyOf(emitted);
        }
    }

    public int activeFlowCount() {
        synchronized (lock) {
            return flowTable.size();
        }
    }

    public void addRule(Rule rule) {
        synchronized (lock) {
            ruleSet.add(rule);
            rebuildAllMatchers(true);
        }
    }

    public boolean removeRule(String ruleId) {
        synchronized (lock) {
            boolean removed = ruleSet.remove(ruleId);
            if (removed) {
                rebuildAllMatchers(false);
            }
            return removed;
        }
    }

    public List<Rule> rules() {
        return ruleSet.snapshot();
    }

    /** Fixed-input reproducible run; returns alerts in deterministic order. */
    public List<Alert> replay(PacketSource source) {
        List<Alert> all = new ArrayList<>();
        for (Packet packet : source.loadAll()) {
            all.addAll(processPacket(packet));
        }
        return List.copyOf(all);
    }

    /** Flush all open aggregation windows (e.g. on shutdown) and commit them. */
    public List<Alert> flushAll() {
        synchronized (lock) {
            List<Alert> emitted = aggregator.flushAll();
            if (!emitted.isEmpty()) {
                sink.emitAll(emitted);
                if (config.persistenceEnabled() && store != null) {
                    store.appendCommit(lastCommittedPosition, emitted);
                }
            }
            return List.copyOf(emitted);
        }
    }

    public void setAnomalyListener(Consumer<TcpAnomalyEvent> listener) {
        synchronized (lock) {
            this.anomalyListener = listener;
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            List<Alert> emitted = aggregator.flushAll();
            deliverAndCommit(emitted);
        }
        if (store != null) {
            store.close();
        }
    }

    private StreamingMatcher matcherFor(TcpFlow flow, Direction direction) {
        EnumMap<Direction, StreamingMatcher> perFlow =
                matchers.computeIfAbsent(flow, k -> new EnumMap<>(Direction.class));
        StreamingMatcher matcher = perFlow.get(direction);
        if (matcher == null) {
            matcher = new StreamingMatcher(ruleSet.snapshot(), config.contextRadius());
            perFlow.put(direction, matcher);
        }
        return matcher;
    }

    private void rebuildAllMatchers(boolean suppressBeforeChange) {
        for (Map.Entry<TcpFlow, EnumMap<Direction, StreamingMatcher>> entry
                : matchers.entrySet()) {
            for (Map.Entry<Direction, StreamingMatcher> perDirection
                    : entry.getValue().entrySet()) {
                StreamingMatcher old = perDirection.getValue();
                StreamingMatcher fresh = new StreamingMatcher(ruleSet.snapshot(),
                        config.contextRadius());
                long reportFrom = suppressBeforeChange ? old.consumed() : 0L;
                fresh.prime(old.tail(), old.consumed(), reportFrom);
                perDirection.setValue(fresh);
            }
        }
    }

    private void flushFlow(TcpFlow flow, List<Alert> emitted) {
        for (Direction direction : flow.readyDirections()) {
            StreamReassembler reassembler = flow.reassembler(direction);
            StreamingMatcher matcher = matchers
                    .getOrDefault(flow, new EnumMap<>(Direction.class))
                    .get(direction);
            if (matcher == null) {
                continue;
            }
            List<ReassembledChunk> remaining = reassembler.pollReady();
            for (ReassembledChunk chunk : remaining) {
                for (MatchHit hit : matcher.feed(chunk.startSeq(), chunk.data())) {
                    MatchHit directed = new MatchHit(hit.rule(), direction,
                            hit.offset(), hit.context());
                    emitted.addAll(aggregator.record(directed, flow.connectionId(),
                            chunk.completionTimestamp()));
                }
            }
        }
        emitted.addAll(aggregator.flush(flow.connectionId()));
        matchers.remove(flow);
    }

    private void commit(long position, List<Alert> emitted) {
        List<Alert> latest = latestById(emitted);
        if (sink != null && !latest.isEmpty()) {
            sink.emitAll(latest);
        }
        if (config.persistenceEnabled() && store != null) {
            store.appendCommit(position, latest);
            store.markDelivered(position);
            lastCommittedPosition = position;
            packetsSinceSnapshot++;
            if (packetsSinceSnapshot >= config.snapshotInterval()) {
                takeSnapshot(position);
                packetsSinceSnapshot = 0;
            }
        } else {
            lastCommittedPosition = position;
        }
    }

    private void deliverAndCommit(List<Alert> emitted) {
        commit(lastCommittedPosition, emitted);
    }

    static List<Alert> latestById(List<Alert> alerts) {
        Map<String, Alert> byId = new java.util.LinkedHashMap<>();
        for (Alert alert : alerts) {
            byId.put(alert.alertId(), alert);
        }
        return List.copyOf(byId.values());
    }

    private void takeSnapshot(long position) {
        List<FlowSnapshot> flows = new ArrayList<>();
        for (TcpFlow flow : flowTable.snapshotFlows()) {
            FlowSnapshot snapshot = flow.capture();
            attachMatcherState(snapshot, Direction.INITIATOR, flow);
            attachMatcherState(snapshot, Direction.RESPONDER, flow);
            flows.add(snapshot);
        }
        store.writeSnapshot(new SnapshotData(position, ruleSet.snapshot(), flows));
    }

    private void attachMatcherState(FlowSnapshot snapshot, Direction direction,
                                    TcpFlow flow) {
        StreamingMatcher matcher = matchers
                .getOrDefault(flow, new EnumMap<>(Direction.class)).get(direction);
        FlowSnapshot.DirectionSnapshot target = direction == Direction.INITIATOR
                ? snapshot.initiator : snapshot.responder;
        if (matcher != null && target != null) {
            target.matcherConsumed = matcher.consumed();
            target.matcherTail = matcher.tail();
        }
    }

    private void recover() {
        if (!config.persistenceEnabled() || store == null) {
            return;
        }
        SnapshotData snapshot = store.readSnapshot();
        long snapshotPosition = -1L;
        if (snapshot != null) {
            snapshotPosition = snapshot.position();
            ruleSet.replaceAll(snapshot.rules());
            for (FlowSnapshot flowSnapshot : snapshot.flows()) {
                TcpFlow flow = TcpFlow.restore(flowSnapshot,
                        config.maxBufferedBytesPerDirection());
                FlowKey key = new FlowKey(flowSnapshot.initiatorIp,
                        flowSnapshot.initiatorPort, flowSnapshot.responderIp,
                        flowSnapshot.responderPort);
                EnumMap<Direction, StreamingMatcher> perFlow = new EnumMap<>(Direction.class);
                restoreMatcher(perFlow, Direction.INITIATOR, flowSnapshot.initiator);
                restoreMatcher(perFlow, Direction.RESPONDER, flowSnapshot.responder);
                matchers.put(flow, perFlow);
                flowTable.register(flow);
            }
        }
        List<com.github.guoyyit.networkidsjava.ids.persistence.CommitRecord> pending =
                store.readCommitsAfter(snapshotPosition);
        long delivered = store.deliveredPosition();
        for (var record : pending) {
            if (record.position() <= delivered) {
                lastCommittedPosition = Math.max(lastCommittedPosition, record.position());
                continue;
            }
            sink.emitAll(record.alerts());
            lastCommittedPosition = Math.max(lastCommittedPosition, record.position());
            store.markDelivered(record.position());
        }
        if (pending.isEmpty() && store.lastCommittedPosition() > snapshotPosition) {
            if (store.lastCommittedPosition() <= delivered) {
                lastCommittedPosition = store.lastCommittedPosition();
                return;
            }
            sink.emitAll(store.lastCommittedAlerts());
            lastCommittedPosition = store.lastCommittedPosition();
            store.markDelivered(lastCommittedPosition);
        }
    }

    private void restoreMatcher(EnumMap<Direction, StreamingMatcher> perFlow,
                                Direction direction,
                                FlowSnapshot.DirectionSnapshot snapshot) {
        if (snapshot == null || snapshot.isn < 0) {
            return;
        }
        StreamingMatcher matcher = new StreamingMatcher(ruleSet.snapshot(),
                config.contextRadius());
        byte[] tail = snapshot.matcherTail == null ? new byte[0] : snapshot.matcherTail;
        matcher.prime(tail, snapshot.matcherConsumed);
        perFlow.put(direction, matcher);
    }

    private void notifyAnomaly(TcpAnomalyEvent event) {
        Consumer<TcpAnomalyEvent> listener = anomalyListener;
        if (listener != null) {
            listener.accept(event);
        }
    }
}
