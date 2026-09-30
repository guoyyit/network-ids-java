package com.github.guoyyit.networkidsjava.alert;

import java.util.Objects;

/**
 * 聚合去重目标: 同一连接(目标) + 同一规则 + 同一方向。
 */
public final class AlertKey {
    private final String ruleId;
    private final String flowIdentity;
    private final String direction;

    public AlertKey(String ruleId, String flowIdentity, String direction) {
        this.ruleId = ruleId;
        this.flowIdentity = flowIdentity;
        this.direction = direction;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getFlowIdentity() {
        return flowIdentity;
    }

    public String getDirection() {
        return direction;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AlertKey other)) {
            return false;
        }
        return Objects.equals(ruleId, other.ruleId)
                && Objects.equals(flowIdentity, other.flowIdentity)
                && Objects.equals(direction, other.direction);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ruleId, flowIdentity, direction);
    }

    @Override
    public String toString() {
        return ruleId + "|" + flowIdentity + "|" + direction;
    }
}
