package com.github.guoyyit.networkidsjava.ids.alert;

/**
 * A (possibly aggregated) emitted alert with match context.
 */
public record Alert(String alertId, String connectionId, String ruleId,
                    long firstTimestamp, long lastTimestamp, long hitCount,
                    String direction, long firstOffset, String contextHex) {
}
