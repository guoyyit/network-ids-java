package com.github.guoyyit.networkidsjava.ids.tcp;

/**
 * Direction of a packet relative to the connection initiator (the side that sent SYN).
 */
public enum Direction {
    INITIATOR,
    RESPONDER,
    UNKNOWN
}
