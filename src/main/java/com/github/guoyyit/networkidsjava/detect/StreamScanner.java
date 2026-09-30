package com.github.guoyyit.networkidsjava.detect;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 在重组后的连续字节流上执行特征匹配。
 * 为每个规则保留跨包边界的部分匹配状态，因此特征跨越多个报文也能命中。
 */
public final class StreamScanner {

    private final Map<String, RuleMatcherState> states = new LinkedHashMap<>();

    public StreamScanner(RuleSet ruleSet) {
        syncRules(ruleSet);
    }

    /** 规则热更新后调用，以当前快照重置匹配器(保留未受影响规则的状态)。 */
    public synchronized void syncRules(RuleSet ruleSet) {
        Map<String, RuleMatcherState> rebuilt = new LinkedHashMap<>();
        for (Rule rule : ruleSet.snapshot()) {
            RuleMatcherState existing = states.get(rule.getId());
            if (existing != null && existing.matches(rule)) {
                rebuilt.put(rule.getId(), existing);
            } else {
                rebuilt.put(rule.getId(), new RuleMatcherState(rule));
            }
        }
        states.clear();
        states.putAll(rebuilt);
    }

    /**
     * 追加一段连续数据。
     *
     * @param data        本段字节
     * @param baseOffset  本段首字节在整条流中的绝对偏移
     */
    public synchronized List<Alert> append(byte[] data, long baseOffset,
                                           AlertContext ctx) {
        List<Alert> hits = new ArrayList<>();
        if (data == null || data.length == 0) {
            return hits;
        }
        for (RuleMatcherState state : states.values()) {
            Rule rule = state.rule;
            if (rule.getDirection() != null && rule.getDirection() != ctx.getDirection()) {
                continue;
            }
            for (RuleMatcherState.Hit hit : state.feed(data)) {
                long off = hit.endLocal();
                long absoluteOffset = baseOffset + off;
                long matchStart = absoluteOffset - rule.contentLength();
                String context = renderContext(hit.contextWindow());
                hits.add(new Alert(rule.getId(), rule.getMessage(),
                        ctx.getFlowKey(), ctx.getDirection(), matchStart, context,
                        ctx.getTimestampMillis(), ctx.getCaptureOrder()));
            }
        }
        return hits;
    }

    /** 取命中点附近的可打印上下文。 */
    private static String renderContext(byte[] window) {
        StringBuilder sb = new StringBuilder();
        for (byte b : window) {
            if (b >= 0x20 && b < 0x7F) {
                sb.append((char) b);
            } else {
                sb.append(String.format("\\x%02X", b));
            }
        }
        return sb.toString();
    }

    /** 构造告警所需的流上下文。 */
    public static final class AlertContext {
        private final FlowKey flowKey;
        private final Direction direction;
        private final long timestampMillis;
        private final long captureOrder;

        public AlertContext(FlowKey flowKey, Direction direction,
                            long timestampMillis, long captureOrder) {
            this.flowKey = flowKey;
            this.direction = direction;
            this.timestampMillis = timestampMillis;
            this.captureOrder = captureOrder;
        }

        public FlowKey getFlowKey() {
            return flowKey;
        }

        public Direction getDirection() {
            return direction;
        }

        public long getTimestampMillis() {
            return timestampMillis;
        }

        public long getCaptureOrder() {
            return captureOrder;
        }
    }

    private static final class RuleMatcherState {
        private static final int CONTEXT_PAD = 8;
        private final Rule rule;
        private final byte[] pattern;
        private final int[] failure;
        private int matched;
        private final java.util.ArrayDeque<Byte> recent = new java.util.ArrayDeque<>();

        private RuleMatcherState(Rule rule) {
            this.rule = rule;
            this.pattern = rule.rawContent();
            this.failure = buildFailure(pattern, rule.isCaseInsensitive());
            this.matched = 0;
        }

        private boolean matches(Rule other) {
            return rule.getId().equals(other.getId())
                    && rule.isCaseInsensitive() == other.isCaseInsensitive()
                    && java.util.Arrays.equals(pattern, other.rawContent())
                    && rule.getDirection() == other.getDirection();
        }

        /** 喂入数据，返回在本段内所有完整命中的结束位置(相对偏移)。 */
        private List<Hit> feed(byte[] data) {
            List<Hit> hits = new ArrayList<>();
            if (pattern.length == 0) {
                return hits;
            }
            for (int i = 0; i < data.length; i++) {
                byte input = data[i];
                recent.addLast(input);
                while (recent.size() > pattern.length + 2L * CONTEXT_PAD) {
                    recent.removeFirst();
                }
                while (matched > 0 && !equal(pattern[matched], input)) {
                    matched = failure[matched - 1];
                }
                if (equal(pattern[matched], input)) {
                    matched++;
                }
                if (matched == pattern.length) {
                    int padEnd = Math.min(data.length - i - 1, CONTEXT_PAD);
                    byte[] window = new byte[recent.size() + padEnd];
                    int wi = 0;
                    for (byte b : recent) {
                        window[wi++] = b;
                    }
                    for (int k = 1; k <= padEnd; k++) {
                        window[wi++] = data[i + k];
                    }
                    hits.add(new Hit(i + 1L, window));
                    matched = failure[matched - 1];
                }
            }
            return hits;
        }

        private boolean equal(byte patternByte, byte inputByte) {
            if (rule.isCaseInsensitive()) {
                return Character.toLowerCase((char) (patternByte & 0xFF))
                        == Character.toLowerCase((char) (inputByte & 0xFF));
            }
            return patternByte == inputByte;
        }

        private static int[] buildFailure(byte[] pattern, boolean ignoreCase) {
            int[] pi = new int[pattern.length];
            for (int i = 1; i < pattern.length; i++) {
                int j = pi[i - 1];
                while (j > 0 && !eq(pattern[i], pattern[j], ignoreCase)) {
                    j = pi[j - 1];
                }
                if (eq(pattern[i], pattern[j], ignoreCase)) {
                    j++;
                }
                pi[i] = j;
            }
            return pi;
        }

        private static boolean eq(byte a, byte b, boolean ignoreCase) {
            if (ignoreCase) {
                return Character.toLowerCase((char) (a & 0xFF))
                        == Character.toLowerCase((char) (b & 0xFF));
            }
            return a == b;
        }

        private record Hit(long endLocal, byte[] contextWindow) {
        }
    }
}
