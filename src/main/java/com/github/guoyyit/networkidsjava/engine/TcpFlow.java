package com.github.guoyyit.networkidsjava.engine;

import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.detect.RuleSet;
import com.github.guoyyit.networkidsjava.detect.StreamScanner;
import com.github.guoyyit.networkidsjava.model.AnomalyEvent;
import com.github.guoyyit.networkidsjava.model.AnomalyType;
import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import com.github.guoyyit.networkidsjava.model.Packet;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import com.github.guoyyit.networkidsjava.model.TcpState;

/**
 * 一条 TCP 连接。
 *
 * <p>连接双方各维护一个独立的"发送端"状态机，状态由该方发出的报文推进，
 * 由该方收到的 ACK/FIN 触发推进。一个报文同时表达"本方发送事件"和
 * "对对端的确认"，因此两个方向都可能被推进。
 *
 * <p>非法状态迁移与畸形报文会被识别并归类为 {@link AnomalyEvent}，
 * 处理被跳过但不会修改既有状态，因而不会导致引擎状态损坏或后续检测错位。
 */
public final class TcpFlow {
    private final FlowKey key;
    private final IdsConfig config;

    private final TcpState[] state = new TcpState[2];
    private final StreamReassembler[] reassemblers = new StreamReassembler[2];
    private final StreamScanner[] scanners = new StreamScanner[2];
    private final long[] initialSeq = new long[2];
    private final boolean[] seqInitialized = new boolean[2];

    private long lastSeenMillis;
    private long createdAtMillis;
    private boolean initiatorResolved;
    private String initiatorIp;
    private int initiatorPort;
    private long timeWaitStartMillis = -1L;

    public TcpFlow(FlowKey key, IdsConfig config, long nowMillis) {
        this.key = key;
        this.config = config;
        this.lastSeenMillis = nowMillis;
        this.createdAtMillis = nowMillis;
        state[0] = TcpState.CLOSED;
        state[1] = TcpState.LISTEN;
    }

    /** 处理一个报文，产出重组数据、告警、异常。 */
    public synchronized FlowResult handle(Packet packet, RuleSet ruleSet) {
        FlowResult result = new FlowResult();
        lastSeenMillis = packet.getTimestampMillis();

        if (!TcpFlags.isValidCombination(packet.getFlags())) {
            result.getAnomalies().add(anomaly(packet,
                    AnomalyType.INVALID_FLAG_COMBINATION,
                    "非法标志组合: 0x" + Integer.toHexString(packet.getFlags())));
            return result;
        }

        Direction direction = resolveDirection(packet);
        int self = direction.ordinal();
        int peer = direction.opposite().ordinal();

        TcpState beforeSelf = state[self];
        if (TcpFlags.isSet(packet.getFlags(), TcpFlags.RST)) {
            // RST 无条件中止整条连接，两个方向都关闭，且不视为非法迁移。
            state[0] = TcpState.CLOSED;
            state[1] = TcpState.CLOSED;
            closeReassembly();
        } else {
            boolean valid = transitionOnSend(self, packet, result);
            if (valid) {
                // 本报文携带的 ACK 作用于对端发送端状态。
                transitionOnAck(peer, packet, result);
            }
        }

        if (packet.payloadLength() > 0) {
            if (state[self] == TcpState.CLOSED || beforeSelf == TcpState.CLOSED) {
                result.getAnomalies().add(anomaly(packet,
                        AnomalyType.DATA_AFTER_CLOSE,
                        "关闭后到达数据, state=" + beforeSelf));
            } else if (!establishedForData(self)) {
                result.getAnomalies().add(anomaly(packet,
                        AnomalyType.DATA_ON_NON_ESTABLISHED,
                        "建连完成前到达数据, state=" + beforeSelf));
            } else {
                deliverPayload(direction, self, packet, ruleSet, result);
            }
        }

        if (state[0] == TcpState.TIME_WAIT || state[1] == TcpState.TIME_WAIT) {
            if (timeWaitStartMillis < 0) {
                timeWaitStartMillis = packet.getTimestampMillis();
            }
        }
        return result;
    }

    /** 该方向自身的发送事件推进。返回 false 表示非法迁移(已记录异常)。 */
    private boolean transitionOnSend(int self, Packet packet, FlowResult result) {
        int flags = packet.getFlags();
        boolean syn = TcpFlags.isSet(flags, TcpFlags.SYN);
        boolean fin = TcpFlags.isSet(flags, TcpFlags.FIN);
        TcpState s = state[self];

        switch (s) {
            case CLOSED:
                if (syn) {
                    state[self] = TcpState.SYN_SENT;
                    recordInitialSeq(self, packet);
                    return true;
                }
                break;
            case LISTEN:
                // 监听方自身发 SYN-ACK(同时打开场景下也可能先 SYN)。
                if (syn) {
                    state[self] = TcpState.SYN_RCVD;
                    recordInitialSeq(self, packet);
                    return true;
                }
                break;
            case SYN_SENT:
                if (syn && TcpFlags.isSet(flags, TcpFlags.ACK)) {
                    state[self] = TcpState.SYN_RCVD;
                    return true;
                }
                break;
            case SYN_RCVD:
                // SYN-ACK 之后通常等待 ACK；本方再发普通 ACK 进入 ESTABLISHED。
                if (!syn && TcpFlags.isSet(flags, TcpFlags.ACK)) {
                    state[self] = TcpState.ESTABLISHED;
                    return true;
                }
                break;
            case ESTABLISHED:
                if (fin) {
                    state[self] = TcpState.FIN_WAIT_1;
                    return true;
                }
                if (TcpFlags.isSet(flags, TcpFlags.ACK) || packet.payloadLength() > 0
                        || TcpFlags.isSet(flags, TcpFlags.PSH)
                        || TcpFlags.isSet(flags, TcpFlags.URG)) {
                    return true;
                }
                break;
            case FIN_WAIT_1, FIN_WAIT_2, CLOSING, TIME_WAIT, CLOSE_WAIT, LAST_ACK:
                // 这些状态的推进依赖对端 ACK/FIN，本方重传或纯 ACK 视为无害。
                if (!fin && !syn) {
                    return true;
                }
                break;
        }
        result.getAnomalies().add(anomaly(packet,
                AnomalyType.ILLEGAL_STATE_TRANSITION,
                "状态 " + s + " 下不允许发送 flags=" + TcpFlags.describe(flags)));
        return false;
    }

    /** 本报文的 ACK 作用于"对端发送端"的状态推进。 */
    private void transitionOnAck(int peer, Packet packet, FlowResult result) {
        if (!TcpFlags.isSet(packet.getFlags(), TcpFlags.ACK)) {
            return;
        }
        TcpState s = state[peer];
        switch (s) {
            case SYN_SENT -> {
                int other = peer == 0 ? 1 : 0;
                // 本报文的发送方若已 SYN_RCVD，则对端 SYN_SENT 被确认、双方建立。
                if (state[other] == TcpState.SYN_RCVD || state[other] == TcpState.ESTABLISHED) {
                    state[peer] = TcpState.ESTABLISHED;
                }
            }
            case SYN_RCVD -> state[peer] = TcpState.ESTABLISHED;
            case FIN_WAIT_1 -> state[peer] = TcpState.FIN_WAIT_2;
            case CLOSING -> state[peer] = TcpState.TIME_WAIT;
            case LAST_ACK -> state[peer] = TcpState.CLOSED;
            default -> { }
        }
    }

    private boolean establishedForData(int self) {
        TcpState s = state[self];
        return switch (s) {
            case ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING -> true;
            default -> false;
        };
    }

    private void recordInitialSeq(int self, Packet packet) {
        if (!seqInitialized[self]) {
            initialSeq[self] = packet.getSeq();
            seqInitialized[self] = true;
        }
    }

    private void deliverPayload(Direction direction, int self, Packet packet,
                                RuleSet ruleSet, FlowResult result) {
        if (reassemblers[self] == null) {
            reassemblers[self] = new StreamReassembler(0L);
        }
        StreamReassembler reassembler = reassemblers[self];
        long base = seqInitialized[self] ? initialSeq[self] : packet.getSeq();
        long relativeSeq = packet.getSeq() - base - 1L;
        byte[] continuous = reassembler.insert(relativeSeq, packet.getPayload());
        if (reassembler.bufferedFragmentCount() > config.getMaxReassemblyFragmentsPerFlow()) {
            reassembler.trimToLimit(config.getMaxReassemblyFragmentsPerFlow());
        }
        if (continuous.length == 0) {
            return;
        }
        long offset = reassembler.getNextOffset() - continuous.length;
        if (scanners[self] == null) {
            scanners[self] = new StreamScanner(ruleSet);
        }
        scanners[self].syncRules(ruleSet);
        FlowResult.ReassembledChunk chunk =
                new FlowResult.ReassembledChunk(direction, offset, continuous);
        result.getChunks().add(chunk);
        StreamScanner.AlertContext ctx = new StreamScanner.AlertContext(
                key, direction, packet.getTimestampMillis(), packet.getCaptureOrder());
        result.getAlerts().addAll(scanners[self].append(continuous, offset, ctx));
    }

    private void closeReassembly() {
        for (int i = 0; i < 2; i++) {
            if (reassemblers[i] != null) {
                reassemblers[i].close();
            }
        }
    }

    private AnomalyEvent anomaly(Packet packet, AnomalyType type, String detail) {
        return new AnomalyEvent(key, type,
                packet.getTimestampMillis(), packet.getCaptureOrder(), detail);
    }

    /** 判断报文方向；若发起方尚未确定则由首个 SYN 决定。 */
    Direction resolveDirection(Packet packet) {
        if (initiatorResolved) {
            boolean fromInitiator = packet.getSrcIp().equals(initiatorIp)
                    && packet.getSrcPort() == initiatorPort;
            return fromInitiator ? Direction.FORWARD : Direction.REVERSE;
        }
        if (TcpFlags.isSet(packet.getFlags(), TcpFlags.SYN)
                && !TcpFlags.isSet(packet.getFlags(), TcpFlags.ACK)) {
            initiatorIp = packet.getSrcIp();
            initiatorPort = packet.getSrcPort();
            initiatorResolved = true;
            return Direction.FORWARD;
        }
        return key.isForward(packet.getSrcIp(), packet.getSrcPort())
                ? Direction.FORWARD : Direction.REVERSE;
    }

    public synchronized TcpState getState(Direction direction) {
        return state[direction.ordinal()];
    }

    public synchronized long getLastSeenMillis() {
        return lastSeenMillis;
    }

    public synchronized long getCreatedAtMillis() {
        return createdAtMillis;
    }

    public FlowKey getKey() {
        return key;
    }

    /** 同步规则热更新到两个方向的扫描器(保留既有跨包匹配状态)。 */
    public synchronized void syncRules(RuleSet ruleSet) {
        for (int i = 0; i < 2; i++) {
            if (scanners[i] != null) {
                scanners[i].syncRules(ruleSet);
            }
        }
    }

    /** 空闲判定。 */
    public synchronized boolean isIdle(long nowMillis) {
        boolean fullyClosed = state[0] == TcpState.CLOSED && state[1] == TcpState.CLOSED;
        if (fullyClosed) {
            return true;
        }
        return nowMillis - lastSeenMillis >= config.getIdleTimeoutMillis();
    }

    /** 僵死(长期无进展且未正常关闭)判定。 */
    public synchronized boolean isZombie(long nowMillis) {
        boolean closed = state[0] == TcpState.CLOSED && state[1] == TcpState.CLOSED;
        return !closed && nowMillis - lastSeenMillis >= config.getZombieTimeoutMillis();
    }

    /** TIME_WAIT 停留是否到期。 */
    public synchronized boolean isTimeWaitExpired(long nowMillis) {
        if (timeWaitStartMillis < 0) {
            return false;
        }
        return nowMillis - timeWaitStartMillis >= config.getTimeWaitMillis();
    }

    /** 是否超过流最大寿命。 */
    public synchronized boolean isLifetimeExceeded(long nowMillis) {
        return nowMillis - createdAtMillis >= config.getMaxFlowLifetimeMillis();
    }
}
