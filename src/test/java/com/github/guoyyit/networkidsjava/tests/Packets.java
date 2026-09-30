package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;

import java.nio.charset.StandardCharsets;

/** 测试用报文构造辅助。 */
final class Packets {
    static final String C_IP = "10.0.0.1";
    static final int C_PORT = 40000;
    static final String S_IP = "10.0.0.2";
    static final int S_PORT = 80;

    private Packets() {
    }

    static Packet of(long order, long ts, String src, int sport, String dst, int dport,
                     long seq, long ack, int flags, String payload) {
        byte[] data = payload == null ? new byte[0]
                : payload.getBytes(StandardCharsets.UTF_8);
        return new Packet(order, ts, src, sport, dst, dport, seq, ack, flags, data);
    }

    static Packet c2s(long order, long ts, long seq, long ack, int flags, String body) {
        return of(order, ts, C_IP, C_PORT, S_IP, S_PORT, seq, ack, flags, body);
    }

    static Packet s2c(long order, long ts, long seq, long ack, int flags, String body) {
        return of(order, ts, S_IP, S_PORT, C_IP, C_PORT, seq, ack, flags, body);
    }

    static int flags(int... bits) {
        int f = 0;
        for (int b : bits) {
            f |= b;
        }
        return f;
    }

    static int ack() {
        return TcpFlags.ACK;
    }
}
