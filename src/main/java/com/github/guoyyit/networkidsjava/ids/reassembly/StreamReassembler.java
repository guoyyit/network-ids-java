package com.github.guoyyit.networkidsjava.ids.reassembly;

import com.github.guoyyit.networkidsjava.ids.persistence.FlowSnapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Per-direction TCP payload reassembler supporting out-of-order, duplicate and
 * overlapping segments with a deterministic, arrival-order-independent overlap rule.
 *
 * <p>Overlap rule (documented and reproducible): for every conflicting byte, the
 * segment with the smallest starting sequence number wins; if both start at the
 * same sequence number, the segment with the smaller capture position wins.
 * Consequently the reassembled byte stream is identical whether packets arrive
 * in order, out of order, duplicated or overlapped.
 *
 * <p>Bytes whose start sequence is within {@code 2^31} ahead of the next expected
 * sequence are treated as future out-of-order data; anything farther behind than
 * the half sequence space is treated as a wrap-around future segment.
 */
public final class StreamReassembler {

    private static final long MOD = 1L << 32;
    private static final long HALF = 1L << 31;

    private final long maxBufferedBytes;
    private final TreeMap<Long, Segment> pending = new TreeMap<>();
    private Long dataBase;
    private long expectedAbs;
    private long streamLength;
    private long bufferedBytes;

    public StreamReassembler(long maxBufferedBytes) {
        this.maxBufferedBytes = maxBufferedBytes;
    }

    public void reset(long isn) {
        this.dataBase = (isn + 1) % MOD;
        this.pending.clear();
        this.expectedAbs = 0L;
        this.streamLength = 0L;
        this.bufferedBytes = 0L;
    }

    /** Reset all state as if no SYN has been seen for this direction yet. */
    public void resetUninitialized() {
        this.dataBase = null;
        this.pending.clear();
        this.expectedAbs = 0L;
        this.streamLength = 0L;
        this.bufferedBytes = 0L;
    }

    /**
     * Enqueue one segment. The whole (newly visible) segment is accepted
     * atomically, or fully rejected when it would exceed the buffer cap.
     *
     * @return number of rejected bytes (0 when accepted)
     */
    public int enqueue(long arrivalPosition, long timestamp, long seq, byte[] data) {
        if (dataBase == null || data == null || data.length == 0) {
            return 0;
        }
        long rel = (seq - dataBase) % MOD;
        if (rel < 0) {
            rel += MOD;
        }
        long expectedRel = expectedAbs % MOD;
        long forward = (rel - expectedRel) % MOD;
        if (forward < 0) {
            forward += MOD;
        }
        long absStart;
        if (forward < HALF) {
            absStart = expectedAbs + forward;
        } else {
            absStart = expectedAbs - (MOD - forward);
        }
        int trimFront = 0;
        if (absStart < expectedAbs) {
            trimFront = (int) Math.min(data.length, expectedAbs - absStart);
            absStart = expectedAbs;
            if (trimFront >= data.length) {
                return 0;
            }
        }
        return accept(arrivalPosition, timestamp, absStart, data, trimFront);
    }

    public List<ReassembledChunk> pollReady() {
        if (dataBase == null) {
            return List.of();
        }
        java.util.List<ReassembledChunk> chunks = new java.util.ArrayList<>();
        while (true) {
            Map.Entry<Long, Segment> next = pending.ceilingEntry(expectedAbs);
            if (next == null || next.getKey() > expectedAbs) {
                break;
            }
            Segment segment = next.getValue();
            byte[] data = segment.data;
            long completion = segment.timestamp;
            long startOffset = streamLength;
            expectedAbs += data.length;
            streamLength += data.length;
            pending.remove(next.getKey());
            bufferedBytes -= data.length;
            while (true) {
                Map.Entry<Long, Segment> adjacent =
                        pending.ceilingEntry(expectedAbs);
                if (adjacent == null || adjacent.getKey() > expectedAbs) {
                    break;
                }
                Segment moreSegment = adjacent.getValue();
                byte[] more = moreSegment.data;
                completion = Math.max(completion, moreSegment.timestamp);
                pending.remove(adjacent.getKey());
                bufferedBytes -= more.length;
                expectedAbs += more.length;
                streamLength += more.length;
                byte[] grown = new byte[data.length + more.length];
                System.arraycopy(data, 0, grown, 0, data.length);
                System.arraycopy(more, 0, grown, data.length, more.length);
                data = grown;
            }
            chunks.add(new ReassembledChunk(startOffset, completion, data));
        }
        return chunks;
    }

    public Long expectedSeq() {
        return dataBase == null ? null : (dataBase + expectedAbs) % MOD;
    }

    public long bufferedBytes() {
        return bufferedBytes;
    }

    public long streamLength() {
        return streamLength;
    }

    public boolean initialized() {
        return dataBase != null;
    }

    /** Export all resumable state (including queued out-of-order segments). */
    public FlowSnapshot.DirectionSnapshot capture() {
        FlowSnapshot.DirectionSnapshot snapshot = new FlowSnapshot.DirectionSnapshot();
        if (dataBase == null) {
            snapshot.isn = -1L;
            snapshot.consumedSeq = 0L;
            snapshot.streamLength = 0L;
            snapshot.segments = List.of();
            return snapshot;
        }
        snapshot.isn = (dataBase - 1) & 0xFFFFFFFFL;
        snapshot.consumedSeq = expectedAbs;
        snapshot.streamLength = streamLength;
        java.util.List<FlowSnapshot.SegmentSnapshot> segments = new java.util.ArrayList<>();
        for (Map.Entry<Long, Segment> entry : pending.entrySet()) {
            FlowSnapshot.SegmentSnapshot segment = new FlowSnapshot.SegmentSnapshot();
            segment.arrivalPosition = entry.getValue().arrival;
            segment.timestamp = entry.getValue().timestamp;
            segment.seq = (dataBase + entry.getKey()) & 0xFFFFFFFFL;
            segment.data = entry.getValue().data.clone();
            segments.add(segment);
        }
        snapshot.segments = segments;
        return snapshot;
    }

    /** Restore state produced by {@link #capture()}. */
    public void restore(FlowSnapshot.DirectionSnapshot snapshot) {
        pending.clear();
        bufferedBytes = 0L;
        if (snapshot == null || snapshot.isn < 0) {
            dataBase = null;
            expectedAbs = 0L;
            streamLength = 0L;
            return;
        }
        reset(snapshot.isn);
        expectedAbs = snapshot.consumedSeq;
        streamLength = snapshot.streamLength;
        for (FlowSnapshot.SegmentSnapshot segment : snapshot.segments) {
            enqueue(segment.arrivalPosition, segment.timestamp, segment.seq, segment.data);
        }
    }

    private int accept(long arrivalPosition, long timestamp, long start, byte[] incoming, int from) {
        long end = start + (incoming.length - from);

        // Newly visible ranges are gaps of [start,end) not covered by existing
        // segments, except where an existing segment wins the overlap rule.
        List<long[]> visible = new java.util.ArrayList<>();
        long windowStart = start;
        long windowEnd = end;
        for (Segment existing : new ArrayList<>(pending.tailMap(Long.MIN_VALUE).values())) {
            if (existing.end() <= start || existing.start() >= end) {
                continue;
            }
            if (existing.start() == start && existing.arrival <= arrivalPosition) {
                windowStart = Math.max(windowStart, existing.end());
            }
        }
        if (windowStart < windowEnd) {
            visible.add(new long[]{windowStart, windowEnd});
            for (Segment existing : pending.subMap(start, true, end, false).values()) {
                if (existing.start() == start && existing.arrival <= arrivalPosition) {
                    continue;
                }
                removeCoverage(visible, existing.start(), Math.min(existing.end(), end));
            }
        }

        long newBytes = 0;
        for (long[] range : visible) {
            newBytes += range[1] - range[0];
        }
        if (bufferedBytes + newBytes > maxBufferedBytes) {
            return (int) (end - start);
        }

        // Remove losing existing segments (earlier start wins; same start keeps
        // the earlier arrival), preserving any non-overlapping tails.
        for (Segment existing : new ArrayList<>(pending.subMap(start, false, end, false)
                .values())) {
            if (existing.end() <= start) {
                continue;
            }
            pending.remove(existing.start());
            bufferedBytes -= existing.data.length;
            if (existing.end() > end) {
                long tailStart = end;
                byte[] tail = new byte[(int) (existing.end() - tailStart)];
                System.arraycopy(existing.data, existing.data.length - tail.length,
                        tail, 0, tail.length);
                pending.put(tailStart, new Segment(tailStart, existing.arrival, existing.timestamp, tail));
                bufferedBytes += tail.length;
            }
        }
        // Same-start case: older arrival wins and kept the whole range already.
        Segment sameStart = pending.get(start);
        if (sameStart != null && sameStart.arrival <= arrivalPosition) {
            return 0;
        }
        if (sameStart != null) {
            pending.remove(start);
            bufferedBytes -= sameStart.data.length;
            if (sameStart.end() > end) {
                byte[] tail = new byte[(int) (sameStart.end() - end)];
                System.arraycopy(sameStart.data, sameStart.data.length - tail.length,
                        tail, 0, tail.length);
                pending.put(end, new Segment(end, sameStart.arrival, sameStart.timestamp, tail));
                bufferedBytes += tail.length;
            }
        }
        // Left-overlap (existing starts before us and wins): trim front.
        Map.Entry<Long, Segment> floor = pending.floorEntry(start);
        int effectiveFrom = from;
        long effectiveStart = start;
        if (floor != null && floor.getValue().end() > start) {
            int skip = (int) (Math.min(floor.getValue().end(), end) - start);
            effectiveFrom += skip;
            effectiveStart += skip;
        }
        if (effectiveStart < end) {
            byte[] piece = slice(incoming, effectiveFrom, incoming.length);
            pending.put(effectiveStart, new Segment(effectiveStart, arrivalPosition, timestamp, piece));
            bufferedBytes += piece.length;
        }
        return 0;
    }

    private static void removeCoverage(List<long[]> ranges, long from, long to) {
        List<long[]> result = new ArrayList<>();
        for (long[] range : ranges) {
            if (to <= range[0] || from >= range[1]) {
                result.add(range);
                continue;
            }
            if (from > range[0]) {
                result.add(new long[]{range[0], from});
            }
            if (to < range[1]) {
                result.add(new long[]{to, range[1]});
            }
        }
        ranges.clear();
        ranges.addAll(result);
    }

    private static byte[] slice(byte[] source, int from, int to) {
        byte[] result = new byte[to - from];
        System.arraycopy(source, from, result, 0, result.length);
        return result;
    }

    private static final class Segment {
        private final long startAbs;
        private final long arrival;
        private final long timestamp;
        private final byte[] data;

        private Segment(long startAbs, long arrival, long timestamp, byte[] data) {
            this.startAbs = startAbs;
            this.arrival = arrival;
            this.timestamp = timestamp;
            this.data = data;
        }

        private long start() {
            return startAbs;
        }

        private long end() {
            return startAbs + data.length;
        }
    }
}
