package com.github.guoyyit.networkidsjava.alert;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 按事件时间做翻滚窗口(tumbling window)聚合去重。
 *
 * <p>窗口边界规则(确定且文档化): 窗口为左闭右开区间
 * {@code [floor(ts/W)*W, floor(ts/W)*W + W)}。同一目标(连接)同一规则同一方向
 * 在同一窗口内的多次命中合并为一条 {@link AggregatedAlert}，携带命中次数、
 * 首次与末次命中时间；窗口为 {@code floor} 对齐，边界上的命中属于新窗口。
 * 当到达属于更晚窗口的事件时，更早的窗口被关闭并刷出；事件时间必须单调不减。
 */
public final class AlertAggregator {

    private final long windowMillis;
    private final TreeMap<Long, Map<AlertKey, MutableAggregate>> windows = new TreeMap<>();

    public AlertAggregator(long windowMillis) {
        if (windowMillis <= 0) {
            throw new IllegalArgumentException("windowMillis 必须为正: " + windowMillis);
        }
        this.windowMillis = windowMillis;
    }

    /** 投递一条命中，返回因窗口关闭而立即刷出的聚合告警(可能为空)。 */
    public List<AggregatedAlert> accept(Alert alert) {
        long windowStart = windowStart(alert.getTimestampMillis());
        List<AggregatedAlert> flushed = flushBefore(windowStart);
        Map<AlertKey, MutableAggregate> window =
                windows.computeIfAbsent(windowStart, k -> new java.util.LinkedHashMap<>());
        AlertKey key = new AlertKey(alert.getRuleId(),
                alert.getFlowKey().identity(), alert.getDirection().name());
        MutableAggregate agg = window.get(key);
        if (agg == null) {
            agg = new MutableAggregate(alert, windowStart, windowStart + windowMillis);
            window.put(key, agg);
        } else {
            agg.record(alert);
        }
        return flushed;
    }

    /** 刷出所有尚未关闭或仍在保留的窗口。 */
    public List<AggregatedAlert> flushAll() {
        List<AggregatedAlert> all = new ArrayList<>();
        for (Map<AlertKey, MutableAggregate> window : windows.values()) {
            for (MutableAggregate agg : window.values()) {
                all.add(agg.toAggregatedAlert());
            }
        }
        windows.clear();
        return all;
    }

    /** 刷出起点严格小于当前窗口的所有窗口。 */
    private List<AggregatedAlert> flushBefore(long currentWindowStart) {
        List<AggregatedAlert> flushed = new ArrayList<>();
        Iterator<Map.Entry<Long, Map<AlertKey, MutableAggregate>>> it =
                windows.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<Long, Map<AlertKey, MutableAggregate>> e = it.next();
            if (e.getKey() >= currentWindowStart) {
                break;
            }
            for (MutableAggregate agg : e.getValue().values()) {
                flushed.add(agg.toAggregatedAlert());
            }
            it.remove();
        }
        return flushed;
    }

    private long windowStart(long timestampMillis) {
        return Math.floorDiv(timestampMillis, windowMillis) * windowMillis;
    }

    private static final class MutableAggregate {
        private final String ruleId;
        private final String message;
        private final com.github.guoyyit.networkidsjava.model.FlowKey flowKey;
        private final com.github.guoyyit.networkidsjava.model.Direction direction;
        private final long windowStart;
        private final long windowEnd;
        private long firstHitMillis;
        private long lastHitMillis;
        private long hitCount;
        private String firstContext;

        MutableAggregate(Alert first, long windowStartMillis, long windowEndMillis) {
            this.ruleId = first.getRuleId();
            this.message = first.getMessage();
            this.flowKey = first.getFlowKey();
            this.direction = first.getDirection();
            this.windowStart = windowStartMillis;
            this.windowEnd = windowEndMillis;
            record(first);
        }

        void record(Alert alert) {
            if (hitCount == 0) {
                this.firstHitMillis = alert.getTimestampMillis();
                this.firstContext = alert.getMatchedContext();
            }
            this.lastHitMillis = alert.getTimestampMillis();
            this.hitCount++;
        }

        AggregatedAlert toAggregatedAlert() {
            return new AggregatedAlert(ruleId, message, flowKey, direction,
                    windowStart, windowEnd,
                    firstHitMillis, lastHitMillis,
                    hitCount, firstContext);
        }
    }
}
