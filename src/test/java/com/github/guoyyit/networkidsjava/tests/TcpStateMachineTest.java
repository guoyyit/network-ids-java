package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.model.TcpFlags;
import com.github.guoyyit.networkidsjava.ids.tcp.Direction;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpAnomalyType;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpState;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpStateMachine;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class TcpStateMachineTest {

    private static Packet packet(int flags) {
        return packet(flags, 0);
    }

    private static Packet packet(int flags, int payloadSize) {
        byte[] payload = new byte[payloadSize];
        return new Packet(0L, "10.0.0.1", 1234, "10.0.0.2", 80,
                100L, 0L, flags, payload);
    }

    @Test
    void fullHandshakeAndOrderlyClose() {
        TcpStateMachine sm = new TcpStateMachine();
        assertNull(sm.onPacket(packet(TcpFlags.SYN), Direction.INITIATOR));
        assertEquals(TcpState.SYN_SENT, sm.state());

        assertNull(sm.onPacket(packet(TcpFlags.SYN | TcpFlags.ACK), Direction.RESPONDER));
        assertEquals(TcpState.SYN_RCVD, sm.state());

        assertNull(sm.onPacket(packet(TcpFlags.ACK), Direction.INITIATOR));
        assertEquals(TcpState.ESTABLISHED, sm.state());

        assertNull(sm.onPacket(packet(TcpFlags.PSH | TcpFlags.ACK, 5),
                Direction.INITIATOR));
        assertEquals(TcpState.ESTABLISHED, sm.state());

        assertNull(sm.onPacket(packet(TcpFlags.FIN | TcpFlags.ACK), Direction.INITIATOR));
        assertEquals(TcpState.FIN_WAIT_1, sm.state());

        assertNull(sm.onPacket(packet(TcpFlags.ACK), Direction.RESPONDER));
        assertEquals(TcpState.FIN_WAIT_2, sm.state());

        assertNull(sm.onPacket(packet(TcpFlags.FIN | TcpFlags.ACK), Direction.RESPONDER));
        assertEquals(TcpState.TIME_WAIT, sm.state());

        assertNull(sm.onPacket(packet(TcpFlags.ACK), Direction.INITIATOR));
        assertEquals(TcpState.TIME_WAIT, sm.state());
    }

    @Test
    void responderFinFirstClose() {
        TcpStateMachine sm = established();
        assertNull(sm.onPacket(packet(TcpFlags.FIN | TcpFlags.ACK), Direction.RESPONDER));
        assertEquals(TcpState.CLOSE_WAIT, sm.state());
        assertNull(sm.onPacket(packet(TcpFlags.ACK), Direction.INITIATOR));
        assertEquals(TcpState.CLOSE_WAIT, sm.state());
        assertNull(sm.onPacket(packet(TcpFlags.FIN | TcpFlags.ACK), Direction.INITIATOR));
        assertEquals(TcpState.LAST_ACK, sm.state());
        assertNull(sm.onPacket(packet(TcpFlags.ACK), Direction.RESPONDER));
        assertEquals(TcpState.CLOSED, sm.state());
    }

    @Test
    void malformedPacketsAreClassifiedAndDoNotMutateState() {
        TcpStateMachine sm = new TcpStateMachine();
        assertEquals(TcpAnomalyType.NULL_SCAN,
                sm.onPacket(packet(0), Direction.UNKNOWN));
        assertEquals(TcpState.NEW, sm.state());

        assertEquals(TcpAnomalyType.MALFORMED_FLAG_COMBINATION,
                sm.onPacket(packet(TcpFlags.SYN | TcpFlags.FIN), Direction.UNKNOWN));
        assertEquals(TcpState.NEW, sm.state());

        assertEquals(TcpAnomalyType.MALFORMED_FLAG_COMBINATION,
                sm.onPacket(packet(TcpFlags.SYN | TcpFlags.RST), Direction.UNKNOWN));

        assertEquals(TcpAnomalyType.DATA_ON_SYN,
                sm.onPacket(packet(TcpFlags.SYN, 3), Direction.INITIATOR));
        assertEquals(TcpState.NEW, sm.state());
    }

    @Test
    void illegalTransitionsAreClassified() {
        TcpStateMachine sm = new TcpStateMachine();
        assertEquals(TcpAnomalyType.DATA_WITHOUT_CONNECTION,
                sm.onPacket(packet(TcpFlags.PSH | TcpFlags.ACK, 4), Direction.INITIATOR));
        assertEquals(TcpAnomalyType.ACK_WITHOUT_CONNECTION,
                sm.onPacket(packet(TcpFlags.ACK), Direction.INITIATOR));
        assertEquals(TcpState.NEW, sm.state());

        TcpStateMachine established = established();
        assertEquals(TcpAnomalyType.SYN_IN_ESTABLISHED_STATE,
                established.onPacket(packet(TcpFlags.SYN), Direction.INITIATOR));
        assertEquals(TcpState.ESTABLISHED, established.state());
    }

    @Test
    void resetAlwaysClosesFromAnyState() {
        TcpStateMachine sm = established();
        assertNull(sm.onPacket(packet(TcpFlags.RST | TcpFlags.ACK), Direction.RESPONDER));
        assertEquals(TcpState.CLOSED, sm.state());
        assertNull(sm.onPacket(packet(TcpFlags.SYN), Direction.INITIATOR));
        assertEquals(TcpState.SYN_SENT, sm.state());
    }

    private static TcpStateMachine established() {
        TcpStateMachine sm = new TcpStateMachine();
        sm.onPacket(packet(TcpFlags.SYN), Direction.INITIATOR);
        sm.onPacket(packet(TcpFlags.SYN | TcpFlags.ACK), Direction.RESPONDER);
        sm.onPacket(packet(TcpFlags.ACK), Direction.INITIATOR);
        return sm;
    }
}
