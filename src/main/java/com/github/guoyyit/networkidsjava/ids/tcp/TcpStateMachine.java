package com.github.guoyyit.networkidsjava.ids.tcp;

import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.model.TcpFlags;

/**
 * Per-connection TCP state machine. Direction is resolved by the owning flow.
 *
 * <p>The machine models a single connection globally (not one endpoint's
 * perspective): the initiator is the side that sent the first SYN. A null
 * result means the packet is accepted (control transition applied and, when it
 * carries payload, the flow may feed the payload to the reassembler). Any
 * non-null result classifies a malformed packet or illegal transition; the
 * packet is dropped without any state change, so engine state can never be
 * corrupted and later detection cannot be shifted.
 */
public final class TcpStateMachine {

    private TcpState state = TcpState.NEW;

    public TcpStateMachine() {
    }

    public TcpState state() {
        return state;
    }

    /**
     * Validate and apply one packet.
     *
     * @return anomaly classification, or {@code null} when the packet is legal
     */
    public TcpAnomalyType onPacket(Packet packet, Direction direction) {
        int flags = packet.flags();
        boolean syn = TcpFlags.has(flags, TcpFlags.SYN);
        boolean ack = TcpFlags.has(flags, TcpFlags.ACK);
        boolean rst = TcpFlags.has(flags, TcpFlags.RST);
        boolean fin = TcpFlags.has(flags, TcpFlags.FIN);
        boolean data = packet.payloadLength() > 0;

        if (flags == 0) {
            return TcpAnomalyType.NULL_SCAN;
        }
        if (syn && rst || syn && fin || rst && fin) {
            return TcpAnomalyType.MALFORMED_FLAG_COMBINATION;
        }
        if (syn && data) {
            return TcpAnomalyType.DATA_ON_SYN;
        }

        boolean initiator = direction == Direction.INITIATOR;
        return switch (state) {
            case NEW -> onNew(syn, ack, rst, data);
            case SYN_SENT -> onSynSent(syn, ack, rst, data, initiator);
            case SYN_RCVD -> onSynRcvd(syn, ack, rst, data, initiator);
            case ESTABLISHED -> onEstablished(syn, rst, fin, initiator);
            case FIN_WAIT_1 -> onFinWait1(ack, rst, fin, data, initiator);
            case FIN_WAIT_2 -> onFinWait2(rst, fin, data, initiator);
            case CLOSE_WAIT -> onCloseWait(ack, rst, fin, data, initiator);
            case CLOSING -> onClosing(ack, rst, fin, initiator);
            case LAST_ACK -> onLastAck(ack, rst, fin, initiator);
            case TIME_WAIT -> onTimeWait(syn, ack, rst, fin, data);
            case CLOSED -> onClosed(syn, ack, rst, data);
        };
    }

    private TcpAnomalyType onNew(boolean syn, boolean ack, boolean rst, boolean data) {
        if (syn && !ack && !rst) {
            state = TcpState.SYN_SENT;
            return null;
        }
        if (rst) {
            return TcpAnomalyType.INVALID_STATE_TRANSITION;
        }
        if (data) {
            return TcpAnomalyType.DATA_WITHOUT_CONNECTION;
        }
        if (ack) {
            return TcpAnomalyType.ACK_WITHOUT_CONNECTION;
        }
        return TcpAnomalyType.INVALID_STATE_TRANSITION;
    }

    private TcpAnomalyType onSynSent(boolean syn, boolean ack, boolean rst,
                                     boolean data, boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (!initiator && syn) {
            state = TcpState.SYN_RCVD;
            return null;
        }
        if (initiator && syn && !ack) {
            return null;
        }
        if (data) {
            return TcpAnomalyType.DATA_WITHOUT_CONNECTION;
        }
        if (ack) {
            return TcpAnomalyType.ACK_WITHOUT_CONNECTION;
        }
        return TcpAnomalyType.INVALID_STATE_TRANSITION;
    }

    private TcpAnomalyType onSynRcvd(boolean syn, boolean ack, boolean rst,
                                     boolean data, boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (initiator && ack && !syn) {
            state = TcpState.ESTABLISHED;
            return null;
        }
        if (syn) {
            return null;
        }
        if (data) {
            return TcpAnomalyType.DATA_WITHOUT_CONNECTION;
        }
        return TcpAnomalyType.INVALID_STATE_TRANSITION;
    }

    private TcpAnomalyType onEstablished(boolean syn, boolean rst, boolean fin,
                                         boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (syn) {
            return TcpAnomalyType.SYN_IN_ESTABLISHED_STATE;
        }
        if (fin) {
            state = initiator ? TcpState.FIN_WAIT_1 : TcpState.CLOSE_WAIT;
            return null;
        }
        return null;
    }

    private TcpAnomalyType onFinWait1(boolean ack, boolean rst, boolean fin,
                                      boolean data, boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (fin && initiator) {
            return null;
        }
        if (fin) {
            state = ack ? TcpState.TIME_WAIT : TcpState.CLOSING;
            return null;
        }
        if (ack && !initiator) {
            state = TcpState.FIN_WAIT_2;
            return null;
        }
        if (data && initiator) {
            return TcpAnomalyType.INVALID_STATE_TRANSITION;
        }
        return null;
    }

    private TcpAnomalyType onFinWait2(boolean rst, boolean fin,
                                      boolean data, boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (fin && !initiator) {
            state = TcpState.TIME_WAIT;
            return null;
        }
        if (data && initiator) {
            return TcpAnomalyType.INVALID_STATE_TRANSITION;
        }
        return null;
    }

    private TcpAnomalyType onCloseWait(boolean ack, boolean rst, boolean fin,
                                       boolean data, boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (fin && initiator) {
            state = TcpState.LAST_ACK;
            return null;
        }
        if (data && !initiator) {
            return TcpAnomalyType.INVALID_STATE_TRANSITION;
        }
        return null;
    }

    private TcpAnomalyType onClosing(boolean ack, boolean rst, boolean fin,
                                     boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (ack && !initiator) {
            state = TcpState.TIME_WAIT;
            return null;
        }
        if (fin) {
            return null;
        }
        return null;
    }

    private TcpAnomalyType onLastAck(boolean ack, boolean rst, boolean fin,
                                     boolean initiator) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (ack && !initiator) {
            state = TcpState.CLOSED;
            return null;
        }
        if (fin) {
            return null;
        }
        return null;
    }

    private TcpAnomalyType onTimeWait(boolean syn, boolean ack, boolean rst,
                                      boolean fin, boolean data) {
        if (rst) {
            state = TcpState.CLOSED;
            return null;
        }
        if (syn) {
            return TcpAnomalyType.SYN_IN_ESTABLISHED_STATE;
        }
        if (data) {
            return TcpAnomalyType.INVALID_STATE_TRANSITION;
        }
        return null;
    }

    private TcpAnomalyType onClosed(boolean syn, boolean ack, boolean rst, boolean data) {
        if (syn && !ack && !rst) {
            state = TcpState.SYN_SENT;
            return null;
        }
        if (rst) {
            return null;
        }
        if (data) {
            return TcpAnomalyType.DATA_WITHOUT_CONNECTION;
        }
        return TcpAnomalyType.INVALID_STATE_TRANSITION;
    }

    public void restore(TcpState state) {
        this.state = state;
    }
}
