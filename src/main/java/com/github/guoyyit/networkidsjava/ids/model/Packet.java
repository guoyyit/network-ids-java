package com.github.guoyyit.networkidsjava.ids.model;

/**
 * A simulated captured TCP/IP packet.
 *
 * <p>{@code position} is the global capture position assigned by the packet source
 * (starting at 0). {@code timestamp} is the capture timestamp in epoch milliseconds;
 * the engine never uses wall-clock time for detection decisions, which keeps replay
 * reproducible.
 */
public record Packet(long position, long timestamp,
                     String srcIp, int srcPort, String dstIp, int dstPort,
                     long seq, long ack, int flags, byte[] payload) {

    public Packet {
        if (srcIp == null || dstIp == null) {
            throw new IllegalArgumentException("ip must not be null");
        }
        payload = payload == null ? new byte[0] : payload.clone();
    }

    public Packet(long timestamp, String srcIp, int srcPort, String dstIp, int dstPort,
                  long seq, long ack, int flags, byte[] payload) {
        this(-1L, timestamp, srcIp, srcPort, dstIp, dstPort, seq, ack, flags, payload);
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    public int payloadLength() {
        return payload.length;
    }

    public Packet withPosition(long position) {
        return new Packet(position, timestamp, srcIp, srcPort, dstIp, dstPort,
                seq, ack, flags, payload);
    }
}
