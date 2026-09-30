package com.github.guoyyit.networkidsjava.model;

/**
 * 一次畸形报文/非法状态迁移事件。
 */
public final class AnomalyEvent {
    private final FlowKey flowKey;
    private final AnomalyType type;
    private final long timestampMillis;
    private final long captureOrder;
    private final String detail;

    public AnomalyEvent(FlowKey flowKey, AnomalyType type,
                        long timestampMillis, long captureOrder, String detail) {
        this.flowKey = flowKey;
        this.type = type;
        this.timestampMillis = timestampMillis;
        this.captureOrder = captureOrder;
        this.detail = detail;
    }

    public FlowKey getFlowKey() {
        return flowKey;
    }

    public AnomalyType getType() {
        return type;
    }

    public long getTimestampMillis() {
        return timestampMillis;
    }

    public long getCaptureOrder() {
        return captureOrder;
    }

    public String getDetail() {
        return detail;
    }

    @Override
    public String toString() {
        return "Anomaly[" + type + "] " + flowKey + " @" + captureOrder + " " + detail;
    }
}
