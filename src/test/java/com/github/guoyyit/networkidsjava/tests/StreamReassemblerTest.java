package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.reassembly.ReassembledChunk;
import com.github.guoyyit.networkidsjava.ids.reassembly.StreamReassembler;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StreamReassemblerTest {

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String drain(StreamReassembler reassembler) {
        StringBuilder sb = new StringBuilder();
        for (ReassembledChunk chunk : reassembler.pollReady()) {
            sb.append(new String(chunk.data(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    @Test
    void inOrderSegments() {
        StreamReassembler r = new StreamReassembler(1024);
        r.reset(1000);
        r.enqueue(0, 0, 1001, bytes("hello "));
        r.enqueue(1, 1, 1007, bytes("world"));
        assertEquals("hello world", drain(r));
    }

    @Test
    void outOfOrderSegmentsReassembleInSequence() {
        StreamReassembler r = new StreamReassembler(1024);
        r.reset(1000);
        r.enqueue(1, 1, 1007, bytes("world"));
        assertTrue(drain(r).isEmpty());
        r.enqueue(0, 0, 1001, bytes("hello "));
        assertEquals("hello world", drain(r));
    }

    @Test
    void duplicateSegmentsAreIgnored() {
        StreamReassembler r = new StreamReassembler(1024);
        r.reset(1000);
        r.enqueue(0, 0, 1001, bytes("hello "));
        r.enqueue(2, 2, 1001, bytes("hello "));
        r.enqueue(1, 1, 1007, bytes("world"));
        assertEquals("hello world", drain(r));
        assertEquals(0, r.bufferedBytes());
    }

    @Test
    void overlapIsDeterministicRegardlessOfArrivalOrder() {
        byte[] expected = orderedResult();
        byte[] reversed = reversedArrivalResult();
        assertArrayEquals(expected, reversed);
        assertEquals("abcdefghij", new String(expected, StandardCharsets.UTF_8));
    }

    private byte[] orderedResult() {
        StreamReassembler r = new StreamReassembler(1024);
        r.reset(0);
        r.enqueue(0, 0, 1, bytes("abcdef"));
        r.enqueue(1, 1, 4, bytes("defghij"));
        return drain(r).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] reversedArrivalResult() {
        StreamReassembler r = new StreamReassembler(1024);
        r.reset(0);
        r.enqueue(1, 1, 4, bytes("defghij"));
        r.enqueue(0, 0, 1, bytes("abcdef"));
        return drain(r).getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void sameStartOverlapEarlierArrivalWins() {
        StreamReassembler first = new StreamReassembler(1024);
        first.reset(0);
        first.enqueue(0, 0, 1, bytes("AAAAAA"));
        first.enqueue(1, 1, 1, bytes("BBBBBB"));
        assertEquals("AAAAAA", drain(first));

        StreamReassembler second = new StreamReassembler(1024);
        second.reset(0);
        second.enqueue(0, 0, 1, bytes("BBBBBB"));
        second.enqueue(1, 1, 1, bytes("AAAAAA"));
        assertEquals("BBBBBB", drain(second));
    }

    @Test
    void gapFillingCanMergeMultipleQueuedSegments() {
        StreamReassembler r = new StreamReassembler(1024);
        r.reset(0);
        r.enqueue(2, 2, 7, bytes("GH"));
        r.enqueue(1, 1, 3, bytes("CDEF"));
        r.enqueue(0, 0, 1, bytes("AB"));
        assertEquals("ABCDEFGH", drain(r));
    }

    @Test
    void bufferCapRejectsNewOutOfOrderBytesAtomically() {
        StreamReassembler r = new StreamReassembler(4);
        r.reset(0);
        int rejected = r.enqueue(0, 0, 3, bytes("XXXXX"));
        assertEquals(5, rejected);
        assertEquals(0, r.bufferedBytes());

        assertEquals(0, r.enqueue(1, 1, 3, bytes("ABCD")));
        assertEquals(4, r.bufferedBytes());
        int rejectedGap = r.enqueue(2, 2, 1, bytes("AB"));
        assertEquals(2, rejectedGap);

        StreamReassembler fillable = new StreamReassembler(8);
        fillable.reset(0);
        fillable.enqueue(1, 1, 3, bytes("CDEFGH"));
        assertEquals(0, fillable.enqueue(2, 2, 1, bytes("AB")));
        assertEquals("ABCDEFGH", drain(fillable));
    }

    @Test
    void sequenceNumberWrapIsHandled() {
        StreamReassembler r = new StreamReassembler(8192);
        long isn = 0xFFFFFFFAL;
        r.reset(isn);
        long firstDataSeq = (isn + 1) & 0xFFFFFFFFL;
        r.enqueue(0, 0, firstDataSeq, bytes("abc"));
        r.enqueue(1, 1, (firstDataSeq + 3) & 0xFFFFFFFFL, bytes("def"));
        assertEquals("abcdef", drain(r));
        assertEquals(6, r.streamLength());
    }
}
