package com.github.guoyyit.networkidsjava.model;

import java.util.Objects;

/**
 * 一条传输层连接的规范化四元组：方向无关(较小端点在前)。
 */
public final class FlowKey {
    private final String srcIp;
    private final int srcPort;
    private final String dstIp;
    private final int dstPort;

    public FlowKey(String srcIp, int srcPort, String dstIp, int dstPort) {
        if (compareEndpoints(srcIp, srcPort, dstIp, dstPort) <= 0) {
            this.srcIp = srcIp;
            this.srcPort = srcPort;
            this.dstIp = dstIp;
            this.dstPort = dstPort;
        } else {
            this.srcIp = dstIp;
            this.srcPort = dstPort;
            this.dstIp = srcIp;
            this.dstPort = srcPort;
        }
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

    /**
     * 判断给定报文端点是否沿规范化 key 的正向(key.src -> key.dst)。
     */
    public boolean isForward(String ip, int port) {
        return srcIp.equals(ip) && srcPort == port;
    }

    public boolean hasEndpoint(String ip, int port) {
        return (srcIp.equals(ip) && srcPort == port)
                || (dstIp.equals(ip) && dstPort == port);
    }

    /** 由任意方向的报文构造规范化 key。 */
    public static FlowKey of(String srcIp, int srcPort, String dstIp, int dstPort) {
        return new FlowKey(srcIp, srcPort, dstIp, dstPort);
    }

    private static int compareEndpoints(String ipA, int portA, String ipB, int portB) {
        int byPort = Integer.compare(portA, portB);
        if (byPort != 0) {
            return byPort;
        }
        return ipA.compareTo(ipB);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FlowKey other)) {
            return false;
        }
        return srcPort == other.srcPort
                && dstPort == other.dstPort
                && Objects.equals(srcIp, other.srcIp)
                && Objects.equals(dstIp, other.dstIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, srcPort, dstIp, dstPort);
    }

    @Override
    public String toString() {
        return srcIp + ":" + srcPort + "->" + dstIp + ":" + dstPort;
    }

    public String identity() {
        return srcIp + ":" + srcPort + "<->" + dstIp + ":" + dstPort;
    }
}
