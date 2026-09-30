package com.github.guoyyit.networkidsjava.ids.persistence;

import java.util.List;

/**
 * Memento of one connection's full resumable state: TCP state, directional ISN
 * anchors and queued (not-yet-reassembled) segments, plus matcher prefix
 * offsets. A snapshot plus the later commit log allows exact recovery without
 * unbounded replay.
 */
public final class FlowSnapshot {

    public String flowKey;
    public long incarnation;
    public String tcpState;
    public long lastSeen;

    public String initiatorIp;
    public int initiatorPort;
    public String responderIp;
    public int responderPort;

    public DirectionSnapshot initiator;
    public DirectionSnapshot responder;

    /** Per-direction resumable state. */
    public static final class DirectionSnapshot {
        public long isn;
        public long consumedSeq;
        public long streamLength;
        public long matcherConsumed;
        public byte[] matcherTail;
        public List<SegmentSnapshot> segments = List.of();
    }

    /** One queued out-of-order/overlapping segment. */
    public static final class SegmentSnapshot {
        public long arrivalPosition;
        public long timestamp;
        public long seq;
        public byte[] data;
    }
}
