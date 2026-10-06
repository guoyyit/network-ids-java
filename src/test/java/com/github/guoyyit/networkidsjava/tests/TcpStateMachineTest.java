package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.RuleSet;
import com.github.guoyyit.networkidsjava.engine.FlowResult;
import com.github.guoyyit.networkidsjava.engine.TcpFlow;
import com.github.guoyyit.networkidsjava.model.AnomalyType;
import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import com.github.guoyyit.networkidsjava.model.TcpState;
import org.junit.jupiter.api.Test;

import static com.github.guoyyit.networkidsjava.tests.Packets.C_IP;
import static com.github.guoyyit.networkidsjava.tests.Packets.C_PORT;
import static com.github.guoyyit.networkidsjava.tests.Packets.S_IP;
import static com.github.guoyyit.networkidsjava.tests.Packets.S_PORT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TcpStateMachineTest {

    private final IdsConfig config = new IdsConfig();
    private final FlowKey key = new FlowKey(C_IP, C_PORT, S_IP, S_PORT);

    private Packet c2s(long order, long seq, long ack, int flags, String body) {
        return Packets.c2s(order, 1000L + order, seq, ack, flags, body);
    }

    private Packet s2c(long order, long seq, long ack, int flags, String body) {
        return Packets.s2c(order, 1000L + order, seq, ack, flags, body);
    }

    private void completeHandshake(TcpFlow flow) {
        flow.handle(c2s(1, 1000, 0, TcpFlags.SYN, null), new RuleSet());
        flow.handle(s2c(2, 5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null), new RuleSet());
        flow.handle(c2s(3, 1001, 5001, TcpFlags.ACK, null), new RuleSet());
    }

    @Test
    void handshakeReachesEstablished() {
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        completeHandshake(flow);
        assertEquals(TcpState.ESTABLISHED, flow.getState(Direction.FORWARD));
        assertEquals(TcpState.ESTABLISHED, flow.getState(Direction.REVERSE));
    }

    @Test
    void dataBeforeEstablishedIsAnomaly() {
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        flow.handle(c2s(1, 1000, 0, TcpFlags.SYN, null), new RuleSet());
        FlowResult result = flow.handle(
                c2s(2, 1001, 0, TcpFlags.ACK, "GET /"), new RuleSet());
        assertTrue(result.getAnomalies().stream()
                .anyMatch(a -> a.getType() == AnomalyType.DATA_ON_NON_ESTABLISHED));
    }

    @Test
    void invalidFlagCombinationIsClassified() {
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        FlowResult result = flow.handle(
                c2s(1, 1000, 0, TcpFlags.SYN | TcpFlags.FIN, null), new RuleSet());
        assertEquals(1, result.getAnomalies().size());
        assertEquals(AnomalyType.INVALID_FLAG_COMBINATION,
                result.getAnomalies().get(0).getType());
    }

    @Test
    void illegalTransitionDoesNotCorruptState() {
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        completeHandshake(flow);
        // 已建立后再发裸 SYN 属于非法迁移。
        FlowResult bad = flow.handle(c2s(9, 9999, 0, TcpFlags.SYN, null), new RuleSet());
        assertTrue(bad.getAnomalies().stream()
                .anyMatch(a -> a.getType() == AnomalyType.ILLEGAL_STATE_TRANSITION));
        // 后续正常数据仍能被处理，状态未损坏。
        FlowResult data = flow.handle(
                c2s(10, 1001, 5001, TcpFlags.ACK | TcpFlags.PSH, "GET"), new RuleSet());
        assertEquals(TcpState.ESTABLISHED, flow.getState(Direction.FORWARD));
        assertTrue(data.getAnomalies().isEmpty());
        assertEquals(1, data.getChunks().size());
    }

    @Test
    void rstClosesBothDirections() {
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        completeHandshake(flow);
        flow.handle(c2s(8, 1001, 5001, TcpFlags.RST, null), new RuleSet());
        assertEquals(TcpState.CLOSED, flow.getState(Direction.FORWARD));
        assertEquals(TcpState.CLOSED, flow.getState(Direction.REVERSE));
    }

    @Test
    void reconnectAfterCloseAcceptsNewHandshake() {
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        completeHandshake(flow);
        flow.handle(c2s(8, 1001, 5001, TcpFlags.RST, null), new RuleSet());

        // 同四元组、新 ISN 的重建握手必须被正常接受，不得产生异常。
        FlowResult syn = flow.handle(c2s(9, 9000, 0, TcpFlags.SYN, null), new RuleSet());
        FlowResult synAck = flow.handle(
                s2c(10, 3000, 9001, TcpFlags.SYN | TcpFlags.ACK, null), new RuleSet());
        FlowResult ack = flow.handle(c2s(11, 9001, 3001, TcpFlags.ACK, null), new RuleSet());
        assertTrue(syn.getAnomalies().isEmpty(), "重建 SYN 被判非法: " + syn.getAnomalies());
        assertTrue(synAck.getAnomalies().isEmpty(),
                "重建 SYN-ACK 被判非法: " + synAck.getAnomalies());
        assertTrue(ack.getAnomalies().isEmpty(), "重建 ACK 被判非法: " + ack.getAnomalies());
        assertEquals(TcpState.ESTABLISHED, flow.getState(Direction.FORWARD));
        assertEquals(TcpState.ESTABLISHED, flow.getState(Direction.REVERSE));

        // 紧随其后的数据必须按新连接的 ISN 从偏移 0 重组交付。
        FlowResult data = flow.handle(
                c2s(12, 9001, 3001, TcpFlags.ACK | TcpFlags.PSH, "GET /"), new RuleSet());
        assertTrue(data.getAnomalies().isEmpty(),
                "重建后的数据被判非法: " + data.getAnomalies());
        assertEquals(1, data.getChunks().size());
        assertEquals(0L, data.getChunks().get(0).getStreamOffset());
        assertEquals("GET /", new String(data.getChunks().get(0).getData(),
                java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    void stalePacketAfterCloseIsClassifiedButDoesNotBlockReconnect() {
        TcpFlow flow = new TcpFlow(key, config, 1000L);
        completeHandshake(flow);
        flow.handle(c2s(8, 1001, 5001, TcpFlags.RST, null), new RuleSet());

        // 陈旧数据报文仍被归类为关闭后到达(确定行为)。
        FlowResult stale = flow.handle(
                c2s(9, 1002, 5001, TcpFlags.ACK | TcpFlags.PSH, "stale"), new RuleSet());
        assertTrue(stale.getAnomalies().stream()
                .anyMatch(a -> a.getType() == AnomalyType.DATA_AFTER_CLOSE));

        // 但随后的新连接握手仍被正常接受。
        FlowResult syn = flow.handle(c2s(10, 9000, 0, TcpFlags.SYN, null), new RuleSet());
        assertTrue(syn.getAnomalies().isEmpty());
        flow.handle(s2c(11, 3000, 9001, TcpFlags.SYN | TcpFlags.ACK, null), new RuleSet());
        flow.handle(c2s(12, 9001, 3001, TcpFlags.ACK, null), new RuleSet());
        assertEquals(TcpState.ESTABLISHED, flow.getState(Direction.FORWARD));
    }
}
