package com.github.guoyyit.networkidsjava.ids.model;

import java.util.Objects;

/**
 * Direction-independent canonical 5-tuple (TCP) identifying a connection.
 * Both directions of a conversation map to the same key.
 */
public final class FlowKey {

    private final String ipA;
    private final int portA;
    private final String ipB;
    private final int portB;

    public FlowKey(String ipA, int portA, String ipB, int portB) {
        this.ipA = ipA;
        this.portA = portA;
        this.ipB = ipB;
        this.portB = portB;
    }

    public static FlowKey of(Packet packet) {
        int cmp = packet.srcIp().compareTo(packet.dstIp());
        if (cmp == 0) {
            cmp = Integer.compare(packet.srcPort(), packet.dstPort());
        }
        if (cmp <= 0) {
            return new FlowKey(packet.srcIp(), packet.srcPort(), packet.dstIp(), packet.dstPort());
        }
        return new FlowKey(packet.dstIp(), packet.dstPort(), packet.srcIp(), packet.srcPort());
    }

    public String ipA() {
        return ipA;
    }

    public int portA() {
        return portA;
    }

    public String ipB() {
        return ipB;
    }

    public int portB() {
        return portB;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FlowKey other)) {
            return false;
        }
        return portA == other.portA && portB == other.portB
                && Objects.equals(ipA, other.ipA) && Objects.equals(ipB, other.ipB);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ipA, portA, ipB, portB);
    }

    @Override
    public String toString() {
        return ipA + ":" + portA + "<->" + ipB + ":" + portB;
    }
}
