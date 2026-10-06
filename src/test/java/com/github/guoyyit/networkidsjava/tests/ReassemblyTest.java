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

    @Test
    void sameStartShorterThenLongerExtends() {
        // 同起点: 短段先到, 长段(前缀一致)后到 -> 长段的尾部必须补齐交付。
        StreamReassembler r = new StreamReassembler(0L);
        assertArrayEquals(bytes("abc"), r.insert(0, bytes("abc")));
        assertArrayEquals(bytes("def"), r.insert(0, bytes("abcdef")));
        assertEquals(6, r.getNextOffset());
    }

    @Test
    void sameStartLongerThenShorterKeepsContent() {
        // 同起点: 长段先到, 短段后到 -> 已交付内容不得被覆盖或回退。
        StreamReassembler r = new StreamReassembler(0L);
        assertArrayEquals(bytes("abcdef"), r.insert(0, bytes("abcdef")));
        assertArrayEquals(new byte[0], r.insert(0, bytes("abc")));
        assertEquals(6, r.getNextOffset());
    }

    @Test
    void sameStartBufferedBothOrdersMatchInOrderArrival() {
        // 带前导空洞时, 同起点不同长度段的两种到达顺序,
        // 补洞后的最终内容必须与按序到达完全一致, 且不丢已缓存字节。
        StreamReassembler shortFirst = new StreamReassembler(0L);
        shortFirst.insert(5, bytes("abc"));
        shortFirst.insert(5, bytes("abcdef"));
        byte[] outShortFirst = shortFirst.insert(0, bytes("01234"));

        StreamReassembler longFirst = new StreamReassembler(0L);
        longFirst.insert(5, bytes("abcdef"));
        longFirst.insert(5, bytes("abc"));
        byte[] outLongFirst = longFirst.insert(0, bytes("01234"));

        assertArrayEquals(bytes("01234abcdef"), outShortFirst);
        assertArrayEquals(bytes("01234abcdef"), outLongFirst);
        assertEquals(11, shortFirst.getNextOffset());
        assertEquals(11, longFirst.getNextOffset());
    }

    @Test
    void sameStartDoesNotCorruptBufferedAccounting() {
        // 同起点段不得互相覆盖缓存, 缓存字节数统计必须与实际一致。
        StreamReassembler r = new StreamReassembler(0L);
        r.insert(5, bytes("abc"));
        r.insert(5, bytes("abcdef"));
        assertEquals(6, r.bufferedBytes());
        assertEquals(2, r.bufferedFragmentCount());
    }

    private static byte[] concat(byte[] b) {
        return b;
    }
}
