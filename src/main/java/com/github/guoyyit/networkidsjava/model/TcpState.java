package com.github.guoyyit.networkidsjava.model;

/**
 * 每条 TCP 流两个方向各自维护的状态机状态。
 */
public enum TcpState {
    LISTEN,
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
