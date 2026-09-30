package com.github.guoyyit.networkidsjava.ids.tcp;

/**
 * Pragmatic RFC 793 connection state tracked by the engine.
 */
public enum TcpState {
    NEW,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED
}
