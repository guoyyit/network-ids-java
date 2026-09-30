package com.github.guoyyit.networkidsjava.alert;

import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;

/**
 * 窗口内聚合后的告警: 同一目标(连接+规则)在一个窗口内只输出一条。
 */
public final class AggregatedAlert {
    private final String ruleId;
    private final String message;
    private final FlowKey flowKey;
    private final Direction direction;
    private final long windowStartMillis;
    private final long windowEndMillis;
    private final long firstHitMillis;
    private final long lastHitMillis;
    private final long hitCount;
    private final String firstContext;

    public AggregatedAlert(String ruleId, String message, FlowKey flowKey, Direction direction,
                           long windowStartMillis, long windowEndMillis,
                           long firstHitMillis, long lastHitMillis,
                           long hitCount, String firstContext) {
        this.ruleId = ruleId;
        this.message = message;
        this.flowKey = flowKey;
        this.direction = direction;
        this.windowStartMillis = windowStartMillis;
        this.windowEndMillis = windowEndMillis;
        this.firstHitMillis = firstHitMillis;
        this.lastHitMillis = lastHitMillis;
        this.hitCount = hitCount;
        this.firstContext = firstContext;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getMessage() {
        return message;
    }

    public FlowKey getFlowKey() {
        return flowKey;
    }

    public Direction getDirection() {
        return direction;
    }

    public long getWindowStartMillis() {
        return windowStartMillis;
    }

    public long getWindowEndMillis() {
        return windowEndMillis;
    }

    public long getFirstHitMillis() {
        return firstHitMillis;
    }

    public long getLastHitMillis() {
        return lastHitMillis;
    }

    public long getHitCount() {
        return hitCount;
    }

    public String getFirstContext() {
        return firstContext;
    }

    @Override
    public String toString() {
        return "AggregatedAlert[" + ruleId + "] " + flowKey
                + " window=[" + windowStartMillis + "," + windowEndMillis + ")"
                + " hits=" + hitCount
                + " first=" + firstHitMillis + " last=" + lastHitMillis;
    }
}
