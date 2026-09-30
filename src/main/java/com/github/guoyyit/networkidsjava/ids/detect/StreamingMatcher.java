package com.github.guoyyit.networkidsjava.ids.detect;

import com.github.guoyyit.networkidsjava.ids.rule.Rule;

import java.util.ArrayList;
import java.util.List;

/**
 * Stateful multi-pattern streaming matcher (Aho-Corasick) that matches rules
 * across chunk boundaries. State is per flow-direction, rule-set version and
 * therefore survives out-of-order reassembly ordering.
 *
 * <p>The matcher carries the automaton state (a trie node id) between chunks,
 * so a pattern whose bytes are split across packets still matches exactly once.
 * Overlapping patterns are all reported. Each hit carries the matched offset
 * plus up to {@code contextRadius} bytes of surrounding stream content.
 */
public final class StreamingMatcher {

    private static final int ALPHABET = 256;

    private final List<Rule> rules;
    private final int contextRadius;
    private final int tailCapacity;
    private final Node[] nodes;
    private final int[][] go;
    private int state;
    private long consumed;
    private long reportFromOffset;
    private byte[] tail = new byte[0];

    public StreamingMatcher(List<Rule> rules, int contextRadius) {
        this.rules = List.copyOf(rules);
        this.contextRadius = contextRadius;
        int longest = 0;
        for (Rule rule : this.rules) {
            longest = Math.max(longest, rule.content().length);
        }
        this.tailCapacity = Math.max(contextRadius, Math.max(0, longest - 1));

        Node root = new Node(0);
        java.util.List<Node> trie = new ArrayList<>();
        trie.add(root);
        for (Rule rule : this.rules) {
            byte[] content = rule.content();
            Node current = root;
            for (byte b : content) {
                int c = b & 0xFF;
                Node next = current.children[c];
                if (next == null) {
                    next = new Node(trie.size());
                    current.children[c] = next;
                    trie.add(next);
                }
                current = next;
            }
            current.outputs.add(rule);
        }

        this.nodes = trie.toArray(new Node[0]);
        this.go = new int[nodes.length][ALPHABET];
        buildFailureLinks(root);
    }

    public List<MatchHit> feed(long baseOffset, byte[] chunk) {
        List<MatchHit> hits = new ArrayList<>();
        for (int i = 0; i < chunk.length; i++) {
            state = go[state][chunk[i] & 0xFF];
            long endOffset = consumed + 1;
            for (Rule rule : nodes[state].outputs) {
                long start = endOffset - rule.content().length;
                if (endOffset <= reportFromOffset) {
                    continue;
                }
                byte[] context = extractContext(baseOffset, chunk, i, start, endOffset);
                hits.add(new MatchHit(rule, null, start, context));
            }
            consumed++;
        }
        updateTail(chunk);
        return hits;
    }

    public long consumed() {
        return consumed;
    }

    public byte[] tail() {
        return tail.clone();
    }

    public int tailCapacity() {
        return tailCapacity;
    }

    /**
     * Prime a freshly built automaton with lookback bytes after a rule-set
     * change. State advances and offsets stay correct, but no hits are
     * reported, so cross-packet matches continue without duplicate alerts.
     */
    public void prime(byte[] lookback, long streamLength) {
        if (lookback.length > tailCapacity) {
            byte[] trimmed = new byte[tailCapacity];
            System.arraycopy(lookback, lookback.length - tailCapacity, trimmed, 0,
                    tailCapacity);
            lookback = trimmed;
        }
        this.consumed = streamLength - lookback.length;
        for (byte b : lookback) {
            state = go[state][b & 0xFF];
            consumed++;
        }
        tail = lookback.clone();
    }

    /**
     * Prime after a rule-set change and suppress any match ending before
     * {@code reportFromOffset}: only hits fully contained in bytes at or after
     * that offset are reported. Existing patterns (present before the change)
     * pass 0, newly added patterns pass the current stream length.
     */
    public void prime(byte[] lookback, long streamLength, long reportFromOffset) {
        prime(lookback, streamLength);
        this.reportFromOffset = reportFromOffset;
    }

    public int automatonState() {
        return state;
    }

    public void restoreState(int automatonState, long consumed) {
        this.state = automatonState;
        this.consumed = consumed;
    }

    private byte[] extractContext(long baseOffset, byte[] chunk, int index,
                                  long matchStart, long matchEnd) {
        long ctxAbsStart = Math.max(0L, matchStart - contextRadius);
        long ctxAbsEnd = matchEnd + contextRadius;
        long tailBase = baseOffset - tail.length;
        long streamLen = baseOffset + chunk.length;
        ctxAbsEnd = Math.min(ctxAbsEnd, streamLen);
        int length = (int) (ctxAbsEnd - ctxAbsStart);
        byte[] context = new byte[length];
        long cursor = ctxAbsStart;
        int written = 0;
        if (cursor < baseOffset) {
            int tailFrom = (int) Math.max(0, cursor - tailBase);
            int tailTo = (int) Math.min(tail.length, baseOffset - tailBase);
            int copy = tailTo - tailFrom;
            System.arraycopy(tail, tailFrom, context, 0, copy);
            written += copy;
            cursor += copy;
        }
        if (cursor < ctxAbsEnd) {
            int chunkFrom = (int) (cursor - baseOffset);
            int chunkTo = (int) Math.min(chunk.length, ctxAbsEnd - baseOffset);
            System.arraycopy(chunk, chunkFrom, context, written, chunkTo - chunkFrom);
        }
        return context;
    }

    private void updateTail(byte[] chunk) {
        if (tailCapacity <= 0) {
            tail = new byte[0];
            return;
        }
        byte[] next = new byte[Math.min(tailCapacity, tail.length + chunk.length)];
        int fromOld = Math.max(0, tail.length - (next.length -
                Math.min(chunk.length, next.length)));
        int oldCount = Math.min(tail.length - fromOld, next.length);
        System.arraycopy(tail, fromOld, next, 0, oldCount);
        int chunkFrom = Math.max(0, chunk.length - (next.length - oldCount));
        System.arraycopy(chunk, chunkFrom, next, oldCount, next.length - oldCount);
        tail = next;
    }

    private void buildFailureLinks(Node root) {
        java.util.Deque<Node> queue = new java.util.ArrayDeque<>();
        for (int c = 0; c < ALPHABET; c++) {
            Node child = root.children[c];
            if (child != null) {
                child.fail = root;
                go[0][c] = child.id;
                queue.add(child);
            } else {
                go[0][c] = 0;
            }
        }
        while (!queue.isEmpty()) {
            Node node = queue.poll();
            int nodeId = node.id;
            nodes[nodeId].outputs.addAll(nodes[node.fail.id].outputs);
            for (int c = 0; c < ALPHABET; c++) {
                Node child = node.children[c];
                if (child != null) {
                    Node failChild = nodes[node.fail.id].children[c];
                    child.fail = failChild != null ? failChild : nodes[go[node.fail.id][c]];
                    go[nodeId][c] = child.id;
                    queue.add(child);
                } else {
                    go[nodeId][c] = go[node.fail.id][c];
                }
            }
        }
    }

    private static final class Node {
        private final int id;
        private final Node[] children = new Node[ALPHABET];
        private Node fail;
        private final List<Rule> outputs = new ArrayList<>();

        private Node(int id) {
            this.id = id;
        }
    }
}
