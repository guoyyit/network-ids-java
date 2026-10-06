package com.github.guoyyit.networkidsjava.engine;

import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.model.AnomalyEvent;
import com.github.guoyyit.networkidsjava.model.AnomalyType;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import com.github.guoyyit.networkidsjava.model.TcpState;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 流表：容量有界、并发安全。
 *
 * <p>回收策略(确定可复现，全部基于事件时间)：
 * <ol>
 *   <li>正常老化：{@link #tick(long)} 回收空闲、僵死、TIME_WAIT 到期、超寿命流；</li>
 *   <li>容量满时按优先级腾位：已关闭 &gt; TIME_WAIT &gt; 最久空闲，
 *       同优先级取 lastSeen 最早(再按 key 字典序)保证确定；</li>
 *   <li>没有任何可回收流时报告 {@link AnomalyType#FLOW_TABLE_FULL}，
 *       拒绝新建但不破坏既有状态。</li>
 * </ol>
 * 检测与回收通过全局表锁 + 流级 synchronized 协同，不会处理到已回收的流。
 */
public final class FlowTable {
    private final IdsConfig config;
    private final Map<FlowKey, TcpFlow> flows = new LinkedHashMap<>();

    public FlowTable(IdsConfig config) {
        this.config = config;
    }

    /** 取或建一条流；容量满时触发确定性回收。被驱逐的流随结果返回(供收尾处理)。 */
    public synchronized AcquireResult acquire(FlowKey key, long nowMillis) {
        TcpFlow existing = flows.get(key);
        if (existing != null) {
            return new AcquireResult(existing, false, List.of());
        }
        List<AnomalyEvent> anomalies = new ArrayList<>();
        List<TcpFlow> evicted = new ArrayList<>();
        if (flows.size() >= config.getMaxFlows()) {
            TcpFlow victim = chooseEvictionVictim(nowMillis);
            if (victim == null) {
                anomalies.add(new AnomalyEvent(key, AnomalyType.FLOW_TABLE_FULL,
                        nowMillis, -1L,
                        "流表已满且无可回收流, maxFlows=" + config.getMaxFlows()));
                return new AcquireResult(null, false, anomalies);
            }
            flows.remove(victim.getKey());
            evicted.add(victim);
        }
        TcpFlow created = new TcpFlow(key, config, nowMillis);
        flows.put(key, created);
        return new AcquireResult(created, true, anomalies, evicted);
    }

    /** 基于事件时间的老化扫描，返回被回收的流。 */
    public synchronized List<TcpFlow> tick(long nowMillis) {
        List<TcpFlow> removed = new ArrayList<>();
        var it = flows.entrySet().iterator();
        while (it.hasNext()) {
            TcpFlow flow = it.next().getValue();
            if (flow.isTimeWaitExpired(nowMillis)
                    || flow.isZombie(nowMillis)
                    || flow.isLifetimeExceeded(nowMillis)
                    || flow.isIdle(nowMillis)) {
                it.remove();
                removed.add(flow);
            }
        }
        return removed;
    }

    /** 容量满时的确定性受害者选择。 */
    private TcpFlow chooseEvictionVictim(long nowMillis) {
        return flows.values().stream()
                .filter(f -> isEvictable(f, nowMillis))
                .min(evictionOrder(nowMillis))
                .orElse(null);
    }

    private boolean isEvictable(TcpFlow flow, long nowMillis) {
        return flow.isIdle(nowMillis)
                || flow.isZombie(nowMillis)
                || flow.isTimeWaitExpired(nowMillis)
                || flow.isLifetimeExceeded(nowMillis)
                || isClosed(flow);
    }

    private boolean isClosed(TcpFlow flow) {
        return flow.getState(com.github.guoyyit.networkidsjava.model.Direction.FORWARD)
                == TcpState.CLOSED
                && flow.getState(com.github.guoyyit.networkidsjava.model.Direction.REVERSE)
                == TcpState.CLOSED;
    }

    private Comparator<TcpFlow> evictionOrder(long nowMillis) {
        return Comparator
                .comparingInt((TcpFlow f) -> evictionPriority(f, nowMillis))
                .thenComparingLong(TcpFlow::getLastSeenMillis)
                .thenComparing(f -> f.getKey().identity());
    }

    /** 数字越小越优先回收。 */
    private int evictionPriority(TcpFlow flow, long nowMillis) {
        if (isClosed(flow)) {
            return 0;
        }
        if (flow.isTimeWaitExpired(nowMillis)) {
            return 1;
        }
        if (flow.isIdle(nowMillis)) {
            return 2;
        }
        if (flow.isZombie(nowMillis)) {
            return 3;
        }
        if (flow.isLifetimeExceeded(nowMillis)) {
            return 4;
        }
        return 5;
    }

    public synchronized int size() {
        return flows.size();
    }

    public synchronized void remove(FlowKey key) {
        flows.remove(key);
    }

    public synchronized TcpFlow get(FlowKey key) {
        return flows.get(key);
    }

    /** acquire 的返回值。 */
    public static final class AcquireResult {
        private final TcpFlow flow;
        private final boolean created;
        private final List<AnomalyEvent> anomalies;
        private final List<TcpFlow> evicted;

        public AcquireResult(TcpFlow flow, boolean created, List<AnomalyEvent> anomalies) {
            this(flow, created, anomalies, List.of());
        }

        public AcquireResult(TcpFlow flow, boolean created, List<AnomalyEvent> anomalies,
                             List<TcpFlow> evicted) {
            this.flow = flow;
            this.created = created;
            this.anomalies = anomalies;
            this.evicted = evicted;
        }

        public TcpFlow getFlow() {
            return flow;
        }

        public boolean isCreated() {
            return created;
        }

        public List<AnomalyEvent> getAnomalies() {
            return anomalies;
        }

        /** 本次 acquire 为腾位而驱逐的流(可能为空)，释放前需收尾处理。 */
        public List<TcpFlow> getEvicted() {
            return evicted;
        }
    }
}
