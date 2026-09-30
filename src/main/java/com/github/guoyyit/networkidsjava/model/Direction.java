package com.github.guoyyit.networkidsjava.model;

/**
 * 报文相对于一条连接的方向。
 * FORWARD: 发起方(连接 key 的 src 端) -> 响应方；REVERSE 相反。
 */
public enum Direction {
    FORWARD,
    REVERSE;

    public Direction opposite() {
        return this == FORWARD ? REVERSE : FORWARD;
    }
}
