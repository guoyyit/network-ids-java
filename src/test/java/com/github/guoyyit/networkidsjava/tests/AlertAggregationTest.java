package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.alert.AlertAggregator;
import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertAggregationTest {

    private final FlowKey key = new FlowKey("10.0.0.1", 1000, "10.0.0.2", 80);

    private Alert hit(long order, long ts, long offset) {
        return new Alert("R1", "msg", key, Direction.FORWARD, offset,
                "ctx", ts, order);
    }

    @Test
    void sameTargetSameRuleAggregatesWithinWindow() {
        AlertAggregator aggregator = new AlertAggregator(100L);
        assertTrue(aggregator.accept(hit(1, 0, 0)).isEmpty());
        assertTrue(aggregator.accept(hit(2, 50, 5)).isEmpty());
        assertTrue(aggregator.accept(hit(3, 99, 9)).isEmpty());
        List<AggregatedAlert> all = aggregator.flushAll();
        assertEquals(1, all.size());
        AggregatedAlert a = all.get(0);
        assertEquals(3L, a.getHitCount());
        assertEquals(0L, a.getFirstHitMillis());
        assertEquals(99L, a.getLastHitMillis());
        assertEquals(0L, a.getWindowStartMillis());
        assertEquals(100L, a.getWindowEndMillis());
    }

    @Test
    void windowBoundaryStartsNewAggregate() {
        AlertAggregator aggregator = new AlertAggregator(100L);
        aggregator.accept(hit(1, 99, 0));
        // ts=100 属于新窗口 [100,200)，触发旧窗口刷出。
        List<AggregatedAlert> flushed = aggregator.accept(hit(2, 100, 1));
        assertEquals(1, flushed.size());
        assertEquals(1L, flushed.get(0).getHitCount());
        aggregator.accept(hit(3, 150, 2));
        List<AggregatedAlert> rest = aggregator.flushAll();
        assertEquals(1, rest.size());
        assertEquals(2L, rest.get(0).getHitCount());
    }

    @Test
    void differentRulesDoNotAggregate() {
        AlertAggregator aggregator = new AlertAggregator(100L);
        aggregator.accept(hit(1, 10, 0));
        aggregator.accept(new Alert("R2", "msg", key, Direction.FORWARD, 0,
                "ctx", 20, 2));
        assertEquals(2, aggregator.flushAll().size());
    }
}
