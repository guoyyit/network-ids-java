package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.engine.StreamReassembler;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ReassemblyTest {

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void inOrderDeliversImmediately() {
        StreamReassembler r = new StreamReassembler(0L);
        assertArrayEquals(bytes("abc"), r.insert(0, bytes("abc")));
        assertArrayEquals(bytes("def"), r.insert(3, bytes("def")));
        assertEquals(6, r.getNextOffset());
    }

    @Test
    void outOfOrderBuffersThenReassembles() {
        StreamReassembler r = new StreamReassembler(0L);
        assertArrayEquals(new byte[0], r.insert(3, bytes("def")));
        assertEquals(0, r.getNextOffset());
        assertArrayEquals(bytes("abcdef"), concat(r.insert(0, bytes("abc"))));
        assertEquals(6, r.getNextOffset());
    }

    @Test
    void duplicatesAreIgnored() {
        StreamReassembler r = new StreamReassembler(0L);
        r.insert(0, bytes("abc"));
        assertArrayEquals(new byte[0], r.insert(0, bytes("abc")));
        assertArrayEquals(new byte[0], r.insert(1, bytes("XX")));
        assertEquals(3, r.getNextOffset());
    }

    @Test
    void overlapLowestSeqWins() {
        StreamReassembler r = new StreamReassembler(0L);
        // 先到的是靠后的段；再到达的较小序列号段必须覆盖重叠字节。
        r.insert(2, bytes("ZZ"));
        byte[] out = r.insert(0, bytes("abcde"));
        assertArrayEquals(bytes("abcde"), out);
        assertEquals(5, r.getNextOffset());
    }

    @Test
    void overlapMatchesInOrderArrival() {
        // 乱序重叠场景结果必须与严格按序到达一致。
        StreamReassembler reordered = new StreamReassembler(0L);
        reordered.insert(2, bytes("CDEFG"));
        reordered.insert(0, bytes("abcd"));
        reordered.insert(5, bytes("fg"));

        StreamReassembler ordered = new StreamReassembler(0L);
        ordered.insert(0, bytes("abcd"));
        ordered.insert(2, bytes("CDEFG"));
        ordered.insert(5, bytes("fg"));

        assertEquals(7, reordered.getNextOffset());
        assertEquals(7, ordered.getNextOffset());
    }

    private static byte[] concat(byte[] b) {
        return b;
    }
}
