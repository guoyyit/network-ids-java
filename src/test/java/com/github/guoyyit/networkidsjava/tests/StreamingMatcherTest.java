package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.detect.MatchHit;
import com.github.guoyyit.networkidsjava.ids.detect.StreamingMatcher;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StreamingMatcherTest {

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void matchesSimpleContentAndReportsOffset() {
        StreamingMatcher matcher = new StreamingMatcher(
                List.of(new Rule("r1", bytes("dog"))), 4);
        List<MatchHit> hits = matcher.feed(0, bytes("xxdogxx"));
        assertEquals(1, hits.size());
        assertEquals(2, hits.get(0).offset());
        assertEquals("r1", hits.get(0).rule().id());
    }

    @Test
    void matchesAcrossChunkBoundaries() {
        StreamingMatcher matcher = new StreamingMatcher(
                List.of(new Rule("secret", bytes("secret"))), 0);
        assertTrue(matcher.feed(0, bytes("absec")).isEmpty());
        assertTrue(matcher.feed(5, bytes("r")).isEmpty());
        List<MatchHit> hits = matcher.feed(6, bytes("etXY"));
        assertEquals(1, hits.size());
        assertEquals(2, hits.get(0).offset());
    }

    @Test
    void reportsAllOverlappingPatterns() {
        StreamingMatcher matcher = new StreamingMatcher(List.of(
                new Rule("a", bytes("ab")), new Rule("b", bytes("abc"))), 0);
        List<MatchHit> hits = matcher.feed(0, bytes("zabc"));
        assertEquals(2, hits.size());
    }

    @Test
    void repeatedMatchesAreAllReported() {
        StreamingMatcher matcher = new StreamingMatcher(
                List.of(new Rule("x", bytes("aa"))), 0);
        List<MatchHit> hits = matcher.feed(0, bytes("aaaaa"));
        assertEquals(4, hits.size());
    }

    @Test
    void contextIncludesSurroundingBytesAcrossChunks() {
        StreamingMatcher matcher = new StreamingMatcher(
                List.of(new Rule("k", bytes("bc"))), 2);
        matcher.feed(0, bytes("ab"));
        List<MatchHit> hits = matcher.feed(2, bytes("cd"));
        assertEquals(1, hits.size());
        assertEquals("abcd", new String(hits.get(0).context(), StandardCharsets.UTF_8));
    }

    @Test
    void primingCarriesStateThroughRuleSetReplacement() {
        StreamingMatcher first = new StreamingMatcher(
                List.of(new Rule("old", bytes("zzzzzz"))), 0);
        first.feed(0, bytes("absec"));

        StreamingMatcher rebuilt = new StreamingMatcher(
                List.of(new Rule("secret", bytes("secret"))), 0);
        rebuilt.prime(first.tail(), first.consumed());
        List<MatchHit> hits = rebuilt.feed(5, bytes("ret"));
        assertEquals(1, hits.size());
        assertEquals(2, hits.get(0).offset());
    }
}
