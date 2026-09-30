package com.github.guoyyit.networkidsjava.alert;

import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;

/**
 * 一次规则命中产生的原始告警(聚合前)。
 */
public final class Alert {
    private final String ruleId;
    private final String message;
    private final FlowKey flowKey;
    private final Direction direction;
    private final long streamOffset;
    private final String matchedContext;
    private final long timestampMillis;
    private final long captureOrder;

    public Alert(String ruleId, String message, FlowKey flowKey, Direction direction,
                 long streamOffset, String matchedContext,
                 long timestampMillis, long captureOrder) {
        this.ruleId = ruleId;
        this.message = message;
        this.flowKey = flowKey;
        this.direction = direction;
        this.streamOffset = streamOffset;
        this.matchedContext = matchedContext;
        this.timestampMillis = timestampMillis;
        this.captureOrder = captureOrder;
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

    public long getStreamOffset() {
        return streamOffset;
    }

    public String getMatchedContext() {
        return matchedContext;
    }

    public long getTimestampMillis() {
        return timestampMillis;
    }

    public long getCaptureOrder() {
        return captureOrder;
    }

    /** 用于提交去重与聚合分窗的稳定标识。 */
    public String identity() {
        return ruleId + "|" + flowKey.identity() + "|" + direction.name()
                + "|" + streamOffset + "|" + captureOrder;
    }

    @Override
    public String toString() {
        return "Alert[" + ruleId + "] " + flowKey + " off=" + streamOffset
                + " @" + captureOrder + " ctx=" + matchedContext;
    }
}
