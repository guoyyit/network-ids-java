package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.alert.AlertAggregator;
import com.github.guoyyit.networkidsjava.ids.detect.MatchHit;
import com.github.guoyyit.networkidsjava.ids.rule.ConcurrentRuleSet;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import com.github.guoyyit.networkidsjava.ids.rule.RuleParseException;
import com.github.guoyyit.networkidsjava.ids.rule.RuleParser;
import com.github.guoyyit.networkidsjava.ids.tcp.Direction;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleAndAggregatorTest {

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void parsesHexAndAsciiRulesAndComments() {
        List<Rule> rules = RuleParser.parse("""
                # a comment
                r1: 41 42 43
                r2: ascii|hello
                r3: hex|deadbeef
                """);
        assertEquals(3, rules.size());
        assertArrayEquals(bytes("ABC"), rules.get(0).content());
        assertArrayEquals(bytes("hello"), rules.get(1).content());
        assertArrayEquals(new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF},
                rules.get(2).content());
    }

    @Test
    void rejectsBadHexAndDuplicateIds() {
        assertThrows(RuleParseException.class, () -> RuleParser.parseLine("r1: abc"));
        assertThrows(RuleParseException.class,
                () -> RuleParser.parse("r1: 41\nr1: 42"));
    }

    @Test
    void ruleSetAddRemoveProducesConsistentSnapshots() {
        ConcurrentRuleSet set = new ConcurrentRuleSet(List.of(new Rule("a", bytes("x"))));
        List<Rule> before = set.snapshot();
        assertEquals(1, before.size());
        set.add(new Rule("b", bytes("y")));
        assertEquals(2, set.snapshot().size());
        assertTrue(set.remove("a"));
        assertEquals(1, set.snapshot().size());
        assertEquals("b", set.snapshot().get(0).id());
        assertFalse(set.remove("missing"));
    }

    @Test
    void aggregatorDeduplicatesWithinWindow() {
        AlertAggregator aggregator = new AlertAggregator(100);
        Rule rule = new Rule("r", bytes("ab"));
        MatchHit hit = new MatchHit(rule, Direction.INITIATOR, 0, new byte[0]);
        List<Alert> first = aggregator.record(hit, "c#1", 0);
        assertEquals(1, first.size());
        assertEquals(1, first.get(0).hitCount());

        List<Alert> repeat = aggregator.record(hit, "c#1", 50);
        assertEquals(1, repeat.size());
        assertEquals(first.get(0).alertId(), repeat.get(0).alertId());
        assertEquals(2, repeat.get(0).hitCount());
        assertEquals(50, repeat.get(0).lastTimestamp());
        // already delivered, a non-forcing flush has nothing new
        assertTrue(aggregator.flushAll().isEmpty());
    }

    @Test
    void aggregatorBoundaryStartsNewWindow() {
        AlertAggregator aggregator = new AlertAggregator(100);
        Rule rule = new Rule("r", bytes("ab"));
        MatchHit hit = new MatchHit(rule, Direction.INITIATOR, 0, new byte[0]);
        aggregator.record(hit, "c#1", 0);
        List<Alert> atBoundary = aggregator.record(hit, "c#1", 100);
        assertEquals(2, atBoundary.size());
        assertEquals(1, atBoundary.get(0).hitCount());
        assertEquals(1, atBoundary.get(1).hitCount());
        List<Alert> again = aggregator.record(hit, "c#1", 140);
        assertEquals(1, again.size());
        List<Alert> rest = aggregator.forceFlushAll();
        assertEquals(1, rest.size());
        assertEquals(2, again.get(0).hitCount());
        assertEquals(100, again.get(0).firstTimestamp());
        assertEquals(140, again.get(0).lastTimestamp());
    }

    @Test
    void aggregatorSeparatesTargetsAndDirections() {
        AlertAggregator aggregator = new AlertAggregator(100);
        Rule rule = new Rule("r", bytes("ab"));
        aggregator.record(new MatchHit(rule, Direction.INITIATOR, 0, new byte[0]),
                "c#1", 0);
        aggregator.record(new MatchHit(rule, Direction.RESPONDER, 0, new byte[0]),
                "c#1", 0);
        aggregator.record(new MatchHit(rule, Direction.INITIATOR, 0, new byte[0]),
                "c#2", 0);
        aggregator.record(new MatchHit(rule, Direction.INITIATOR,
                0, new byte[0]), "c#3", 0);
        assertEquals(4, aggregator.forceFlushAll().size());
    }
}
