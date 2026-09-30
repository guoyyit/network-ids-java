package com.github.guoyyit.networkidsjava.ids.tcp;

/**
 * Classification of malformed packets and illegal state transitions.
 */
public enum TcpAnomalyType {
    MALFORMED_PORT,
    MALFORMED_FLAG_COMBINATION,
    NULL_SCAN,
    DATA_ON_SYN,
    SYN_IN_ESTABLISHED_STATE,
    DATA_WITHOUT_CONNECTION,
    ACK_WITHOUT_CONNECTION,
    INVALID_STATE_TRANSITION,
    REASSEMBLY_LIMIT_EXCEEDED
}
