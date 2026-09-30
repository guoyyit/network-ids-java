package com.github.guoyyit.networkidsjava.ids.flow;

import com.github.guoyyit.networkidsjava.ids.model.FlowKey;
import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.model.TcpFlags;
import com.github.guoyyit.networkidsjava.ids.persistence.FlowSnapshot;
import com.github.guoyyit.networkidsjava.ids.reassembly.StreamReassembler;
import com.github.guoyyit.networkidsjava.ids.tcp.Direction;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpAnomalyEvent;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpAnomalyType;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpState;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpStateMachine;

import java.util.List;

/**
 * Per-connection state: TCP state machine, two directional reassemblers,
 * sequence-number anchors, last-seen bookkeeping and incarnation counter.
 */
public final class TcpFlow {

    private final FlowKey key;
    private final TcpStateMachine stateMachine = new TcpStateMachine();
    private final StreamReassembler initiatorStream;
    private final StreamReassembler responderStream;
    private String initiatorIp;
    private int initiatorPort = -1;
    private String responderIp;
    private int responderPort = -1;
    private long incarnation = 1L;
    private long lastSeen;
    private long lastReassemblyRejectedPosition = -1L;

    public TcpFlow(FlowKey key, long maxBufferedBytes) {
        this.key = key;
        this.initiatorStream = new StreamReassembler(maxBufferedBytes);
        this.responderStream = new StreamReassembler(maxBufferedBytes);
    }

    public FlowKey key() {
        return key;
    }

    public long incarnation() {
        return incarnation;
    }

    public TcpState state() {
        return stateMachine.state();
    }

    public long lastSeen() {
        return lastSeen;
    }

    public TcpAnomalyEvent handlePacket(Packet packet) {
        lastSeen = packet.timestamp();
        int flags = packet.flags();
        boolean syn = TcpFlags.has(flags, TcpFlags.SYN);
        boolean synOnly = syn && !TcpFlags.has(flags, TcpFlags.ACK)
                && !TcpFlags.has(flags, TcpFlags.RST)
                && !TcpFlags.has(flags, TcpFlags.FIN);
        boolean synAck = syn && TcpFlags.has(flags, TcpFlags.ACK)
                && !TcpFlags.has(flags, TcpFlags.RST)
                && !TcpFlags.has(flags, TcpFlags.FIN);
        if (synOnly) {
            boolean reincarnate = stateMachine.state() == TcpState.CLOSED;
            if (reincarnate) {
                incarnation++;
                initiatorStream.reset(packet.seq());
                responderStream.resetUninitialized();
            }
            if (reincarnate || initiatorIp == null) {
                designateInitiator(packet);
            }
        }

        Direction direction = resolveDirection(packet);
        TcpAnomalyType anomaly = stateMachine.onPacket(packet, direction);
        if (anomaly != null) {
            return new TcpAnomalyEvent(packet.position(), packet.timestamp(), key,
                    direction, anomaly,
                    "flags=" + TcpFlags.format(flags) + " state=" + stateMachine.state());
        }

        StreamReassembler target = reassembler(direction);
        if (synOnly && direction == Direction.INITIATOR) {
            target.reset(packet.seq());
        } else if (synAck && direction == Direction.RESPONDER
                && !responderStream.initialized()) {
            responderStream.reset(packet.seq());
        } else if (direction != Direction.UNKNOWN && packet.payloadLength() > 0
                && target.initialized()) {
            int rejected = target.enqueue(packet.position(), packet.timestamp(),
                    packet.seq(),
                    packet.payload());
            if (rejected > 0 && packet.position() != lastReassemblyRejectedPosition) {
                lastReassemblyRejectedPosition = packet.position();
                return new TcpAnomalyEvent(packet.position(), packet.timestamp(), key,
                        direction, TcpAnomalyType.REASSEMBLY_LIMIT_EXCEEDED,
                        "rejectedBytes=" + rejected);
            }
        }
        return null;
    }

    public StreamReassembler reassembler(Direction direction) {
        return switch (direction) {
            case INITIATOR -> initiatorStream;
            case RESPONDER -> responderStream;
            default -> null;
        };
    }

    public List<Direction> readyDirections() {
        java.util.List<Direction> ready = new java.util.ArrayList<>(2);
        if (initiatorStream.initialized()) {
            ready.add(Direction.INITIATOR);
        }
        if (responderStream.initialized()) {
            ready.add(Direction.RESPONDER);
        }
        return ready;
    }

    public String connectionId() {
        return key + "#" + incarnation;
    }

    public String initiatorIp() {
        return initiatorIp;
    }

    public int initiatorPort() {
        return initiatorPort;
    }

    public String responderIp() {
        return responderIp;
    }

    public int responderPort() {
        return responderPort;
    }

    public void touch(long timestamp) {
        this.lastSeen = timestamp;
    }

    private void designateInitiator(Packet packet) {
        initiatorIp = packet.srcIp();
        initiatorPort = packet.srcPort();
        responderIp = packet.dstIp();
        responderPort = packet.dstPort();
    }

    private Direction resolveDirection(Packet packet) {
        if (initiatorIp == null) {
            return Direction.UNKNOWN;
        }
        if (packet.srcIp().equals(initiatorIp) && packet.srcPort() == initiatorPort) {
            return Direction.INITIATOR;
        }
        if (packet.srcIp().equals(responderIp) && packet.srcPort() == responderPort) {
            return Direction.RESPONDER;
        }
        return Direction.UNKNOWN;
    }

    /** Export resumable state for a durable snapshot. */
    public FlowSnapshot capture() {
        FlowSnapshot snapshot = new FlowSnapshot();
        snapshot.flowKey = key.toString();
        snapshot.incarnation = incarnation;
        snapshot.tcpState = stateMachine.state().name();
        snapshot.lastSeen = lastSeen;
        snapshot.initiatorIp = initiatorIp;
        snapshot.initiatorPort = initiatorPort;
        snapshot.responderIp = responderIp;
        snapshot.responderPort = responderPort;
        snapshot.initiator = initiatorStream.capture();
        snapshot.responder = responderStream.capture();
        return snapshot;
    }

    /** Rebuild a flow from a durable snapshot. */
    public static TcpFlow restore(FlowSnapshot snapshot, long maxBufferedBytes) {
        FlowKey key = new FlowKey(snapshot.initiatorIp, snapshot.initiatorPort,
                snapshot.responderIp, snapshot.responderPort);
        TcpFlow flow = new TcpFlow(key, maxBufferedBytes);
        flow.incarnation = snapshot.incarnation;
        flow.lastSeen = snapshot.lastSeen;
        flow.initiatorIp = snapshot.initiatorIp;
        flow.initiatorPort = snapshot.initiatorPort;
        flow.responderIp = snapshot.responderIp;
        flow.responderPort = snapshot.responderPort;
        flow.initiatorStream.restore(snapshot.initiator);
        flow.responderStream.restore(snapshot.responder);
        flow.stateMachine.restore(TcpState.valueOf(snapshot.tcpState));
        return flow;
    }
}
