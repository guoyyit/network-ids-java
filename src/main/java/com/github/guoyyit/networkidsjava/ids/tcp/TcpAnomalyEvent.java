package com.github.guoyyit.networkidsjava.ids.tcp;

import com.github.guoyyit.networkidsjava.ids.model.FlowKey;

/**
 * A single classified anomaly. Anomalous packets are never fed to the reassembler,
 * so they cannot corrupt engine state or shift later detection.
 */
public record TcpAnomalyEvent(long position, long timestamp, FlowKey flowKey,
                              Direction direction, TcpAnomalyType type, String detail) {
}
