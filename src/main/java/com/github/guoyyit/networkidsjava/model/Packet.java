package com.github.guoyyit.networkidsjava.model;

/**
 * 模拟抓取到的单个报文(不可变)。
 */
public final class Packet {
    private final long captureOrder;
    private final long timestampMillis;
    private final String srcIp;
    private final int srcPort;
    private final String dstIp;
    private final int dstPort;
    private final long seq;
    private final long ack;
    private final int flags;
    private final byte[] payload;

    public Packet(long captureOrder, long timestampMillis,
                  String srcIp, int srcPort, String dstIp, int dstPort,
                  long seq, long ack, int flags, byte[] payload) {
        this.captureOrder = captureOrder;
        this.timestampMillis = timestampMillis;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.seq = seq;
        this.ack = ack;
        this.flags = flags;
        this.payload = payload == null ? new byte[0] : payload.clone();
    }

    public long getCaptureOrder() {
        return captureOrder;
    }

    public long getTimestampMillis() {
        return timestampMillis;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public String getDstIp() {
        return dstIp;
    }

    public int getDstPort() {
        return dstPort;
    }

    public long getSeq() {
        return seq;
    }

    public long getAck() {
        return ack;
    }

    public int getFlags() {
        return flags;
    }

    public byte[] getPayload() {
        return payload.clone();
    }

    public int payloadLength() {
        return payload.length;
    }

    @Override
    public String toString() {
        return "Packet#" + captureOrder + " " + srcIp + ":" + srcPort
                + "->" + dstIp + ":" + dstPort + " seq=" + seq
                + " flags=0x" + Integer.toHexString(flags)
                + " len=" + payload.length;
    }

}
