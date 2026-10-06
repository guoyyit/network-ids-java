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
    void overlapContentMatchesInOrderArrival() {
        // 与上一场景相同，但逐字节比较交付内容而非仅比较进度。
        StreamReassembler reordered = new StreamReassembler(0L);
        StringBuilder reorderedOut = new StringBuilder();
        reorderedOut.append(new String(reordered.insert(2, bytes("CDEFG")), StandardCharsets.UTF_8));
        reorderedOut.append(new String(reordered.insert(0, bytes("abcd")), StandardCharsets.UTF_8));
        reorderedOut.append(new String(reordered.insert(5, bytes("fg")), StandardCharsets.UTF_8));

        StreamReassembler ordered = new StreamReassembler(0L);
        StringBuilder orderedOut = new StringBuilder();
        orderedOut.append(new String(ordered.insert(0, bytes("abcd")), StandardCharsets.UTF_8));
        orderedOut.append(new String(ordered.insert(2, bytes("CDEFG")), StandardCharsets.UTF_8));
        orderedOut.append(new String(ordered.insert(5, bytes("fg")), StandardCharsets.UTF_8));

        assertEquals(orderedOut.toString(), reorderedOut.toString());
    }

    @Test
    void sameStartLongerArrivesLaterKeepsBufferedPrefix() {
        // 前方有洞，两段都被缓存：短段先到，同起点的更长段后到。
        // 结果必须与按序到达(短段交付后长段补尾部)完全一致。
        StreamReassembler r = new StreamReassembler(0L);
        assertArrayEquals(new byte[0], r.insert(10, bytes("HELLO")));
        assertArrayEquals(new byte[0], r.insert(10, bytes("HELLOWORLD")));
        // 补洞后一次性交付洞内容 + 已缓存的完整长段。
        assertArrayEquals(bytes("0123456789HELLOWORLD"), r.insert(0, bytes("0123456789")));
        assertEquals(20, r.getNextOffset());
    }

    @Test
    void sameStartShorterArrivesLaterDoesNotTruncate() {
        // 前方有洞：长段先缓存，同起点的更短段后到。
        // 短段被完全覆盖必须整体忽略，不得截断已缓存的长段。
        StreamReassembler r = new StreamReassembler(0L);
        assertArrayEquals(new byte[0], r.insert(10, bytes("HELLOWORLD")));
        assertArrayEquals(new byte[0], r.insert(10, bytes("HELLO")));
        // 补洞后一次性交付洞内容 + 已缓存的完整长段(短段不得截断它)。
        assertArrayEquals(bytes("0123456789HELLOWORLD"), r.insert(0, bytes("0123456789")));
        assertEquals(20, r.getNextOffset());
    }

    @Test
    void sameStartAnyOrderMatchesInOrderArrival() {
        // 按序到达基准(两种顺序结果相同，因为重叠部分内容一致)。
        StreamReassembler inOrder = new StreamReassembler(0L);
        StringBuilder expected = new StringBuilder();
        expected.append(new String(inOrder.insert(0, bytes("HELLO")), StandardCharsets.UTF_8));
        expected.append(new String(inOrder.insert(0, bytes("HELLOWORLD")), StandardCharsets.UTF_8));
        assertEquals("HELLOWORLD", expected.toString());

        // 乱序+缓存：短先长后。
        StreamReassembler shortFirst = new StreamReassembler(0L);
        StringBuilder a = new StringBuilder();
        a.append(new String(shortFirst.insert(10, bytes("HELLO")), StandardCharsets.UTF_8));
        a.append(new String(shortFirst.insert(10, bytes("HELLOWORLD")), StandardCharsets.UTF_8));
        a.append(new String(shortFirst.insert(0, bytes("0123456789")), StandardCharsets.UTF_8));

        // 乱序+缓存：长先短后。
        StreamReassembler longFirst = new StreamReassembler(0L);
        StringBuilder b = new StringBuilder();
        b.append(new String(longFirst.insert(10, bytes("HELLOWORLD")), StandardCharsets.UTF_8));
        b.append(new String(longFirst.insert(10, bytes("HELLO")), StandardCharsets.UTF_8));
        b.append(new String(longFirst.insert(0, bytes("0123456789")), StandardCharsets.UTF_8));

        assertEquals("0123456789" + expected, a.toString());
        assertEquals("0123456789" + expected, b.toString());
    }

    @Test
    void sameStartAtDeliveryPointAppendsOnlyTail() {
        // 在交付点上：短段已交付，同起点长段到达只补交付尾部，不重复字节。
        StreamReassembler r = new StreamReassembler(0L);
        assertArrayEquals(bytes("HELLO"), r.insert(0, bytes("HELLO")));
        assertArrayEquals(bytes("WORLD"), r.insert(0, bytes("HELLOWORLD")));
        // 反向：长段先交付，短段整体为重复。
        StreamReassembler r2 = new StreamReassembler(0L);
        assertArrayEquals(bytes("HELLOWORLD"), r2.insert(0, bytes("HELLOWORLD")));
        assertArrayEquals(new byte[0], r2.insert(0, bytes("HELLO")));
        assertEquals(10, r2.getNextOffset());
    }

    private static byte[] concat(byte[] b) {
        return b;
    }
}
