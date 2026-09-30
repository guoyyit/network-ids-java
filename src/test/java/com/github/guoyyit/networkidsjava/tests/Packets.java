package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.model.TcpFlags;

import java.nio.charset.StandardCharsets;

/** TCP packet builder for tests using the 10.0.0.1:1000 <-> 10.0.0.2:80 flow. */
final class Packets {

    static final String C1 = "10.0.0.1";
    static final String C2 = "10.0.0.2";
    static final int P1 = 1000;
    static final int P2 = 80;

    private Packets() {
    }

    static Packet syn(long ts, long seq) {
        return new Packet(ts, C1, P1, C2, P2, seq, 0, TcpFlags.SYN, new byte[0]);
    }

    static Packet synAck(long ts, long seq) {
        return new Packet(ts, C2, P2, C1, P1, seq, 0,
                TcpFlags.SYN | TcpFlags.ACK, new byte[0]);
    }

    static Packet ack(long ts, String from, int fromPort, String to, int toPort) {
        return new Packet(ts, from, fromPort, to, toPort, 0, 0,
                TcpFlags.ACK, new byte[0]);
    }

    static Packet data(long ts, String from, int fromPort, String to, int toPort,
                       long seq, String text) {
        return new Packet(ts, from, fromPort, to, toPort, seq, 0,
                TcpFlags.PSH | TcpFlags.ACK, text.getBytes(StandardCharsets.UTF_8));
    }

    static Packet data(long ts, String from, int fromPort, String to, int toPort,
                       long seq, byte[] payload) {
        return new Packet(ts, from, fromPort, to, toPort, seq, 0,
                TcpFlags.PSH | TcpFlags.ACK, payload);
    }

    static Packet fin(long ts, String from, int fromPort, String to, int toPort) {
        return new Packet(ts, from, fromPort, to, toPort, 0, 0,
                TcpFlags.FIN | TcpFlags.ACK, new byte[0]);
    }

    static Packet rst(long ts, String from, int fromPort, String to, int toPort) {
        return new Packet(ts, from, fromPort, to, toPort, 0, 0,
                TcpFlags.RST | TcpFlags.ACK, new byte[0]);
    }

    static Packet flags(long ts, String from, int fromPort, String to, int toPort,
                        int flags) {
        return new Packet(ts, from, fromPort, to, toPort, 0, 0, flags, new byte[0]);
    }
}
