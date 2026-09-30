package com.github.guoyyit.networkidsjava.ids.flow;

import com.github.guoyyit.networkidsjava.ids.model.FlowKey;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpState;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Bounded flow table with capacity limit, idle/dead ageing and deterministic
 * forced eviction of the least recently seen flow.
 *
 * <p>Expiry policy (evaluated against packet timestamps, not wall clock):
 * <ul>
 *   <li>any flow idle for longer than {@code idleTimeoutMs} is reclaimed;</li>
 *   <li>a flow in a terminal state (CLOSED/TIME_WAIT) is reclaimed after the
 *       shorter {@code closedTimeoutMs} (stale/dead connection cleanup);</li>
 *   <li>when the table is full, the least recently seen flow is forcibly
 *       evicted before the new flow is created.</li>
 * </ul>
 * Every eviction first invokes the {@code onEvict} callback so the engine can
 * flush in-flight reassembled data and open alert windows; therefore no
 * in-flight match is lost.
 */
public final class FlowTable {

    private final int capacity;
    private final long idleTimeoutMs;
    private final long closedTimeoutMs;
    private final LinkedHashMap<FlowKey, TcpFlow> flows;

    public FlowTable(int capacity, long idleTimeoutMs, long closedTimeoutMs) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
        this.idleTimeoutMs = idleTimeoutMs;
        this.closedTimeoutMs = closedTimeoutMs;
        this.flows = new LinkedHashMap<>(16, 0.75f, true);
    }

    public synchronized TcpFlow getOrCreate(FlowKey key, long timestamp,
                                            long maxBufferedBytes) {
        TcpFlow existing = flows.get(key);
        if (existing != null) {
            existing.touch(timestamp);
            return existing;
        }
        TcpFlow created = new TcpFlow(key, maxBufferedBytes);
        created.touch(timestamp);
        flows.put(key, created);
        return created;
    }

    public synchronized TcpFlow get(FlowKey key) {
        return flows.get(key);
    }

    /** Register a flow restored from a durable snapshot. */
    public synchronized void register(TcpFlow flow) {
        flows.put(flow.key(), flow);
    }

    public synchronized int size() {
        return flows.size();
    }

    public synchronized void touch(TcpFlow flow, long timestamp) {
        flow.touch(timestamp);
        flows.get(flow.key());
    }

    public synchronized void evictExpired(long now, Consumer<TcpFlow> onEvict) {
        List<TcpFlow> expired = new ArrayList<>();
        for (Iterator<Map.Entry<FlowKey, TcpFlow>> it = flows.entrySet().iterator();
             it.hasNext(); ) {
            TcpFlow flow = it.next().getValue();
            if (isExpired(flow, now)) {
                expired.add(flow);
                it.remove();
            }
        }
        expired.forEach(onEvict);
    }

    public synchronized TcpFlow evictOldest(long timestamp, Consumer<TcpFlow> onEvict) {
        if (flows.isEmpty()) {
            return null;
        }
        Iterator<Map.Entry<FlowKey, TcpFlow>> it = flows.entrySet().iterator();
        Map.Entry<FlowKey, TcpFlow> oldest = it.next();
        it.remove();
        TcpFlow flow = oldest.getValue();
        flow.touch(timestamp);
        onEvict.accept(flow);
        return flow;
    }

    public synchronized void evict(TcpFlow flow, Consumer<TcpFlow> onEvict) {
        if (flows.remove(flow.key()) != null) {
            onEvict.accept(flow);
        }
    }

    public synchronized int capacity() {
        return capacity;
    }

    public synchronized List<TcpFlow> snapshotFlows() {
        return new ArrayList<>(flows.values());
    }

    private boolean isExpired(TcpFlow flow, long now) {
        long age = now - flow.lastSeen();
        TcpState state = flow.state();
        if (state == TcpState.CLOSED || state == TcpState.TIME_WAIT) {
            return age >= closedTimeoutMs;
        }
        return age >= idleTimeoutMs;
    }
}
