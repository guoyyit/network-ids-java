package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.config.IdsConfig;
import com.github.guoyyit.networkidsjava.engine.FlowTable;
import com.github.guoyyit.networkidsjava.engine.TcpFlow;
import com.github.guoyyit.networkidsjava.model.AnomalyType;
import com.github.guoyyit.networkidsjava.model.Direction;
import com.github.guoyyit.networkidsjava.model.FlowKey;
import com.github.guoyyit.networkidsjava.model.TcpFlags;
import com.github.guoyyit.networkidsjava.model.TcpState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FlowCapacityTest {

    private FlowKey key(int i) {
        return new FlowKey("10.0.0." + i, 1000 + i, "10.1.0.1", 80);
    }

    @Test
    void capacityIsBoundedAndEvictsClosedFirst() {
        IdsConfig config = new IdsConfig();
        config.setMaxFlows(3);
        FlowTable table = new FlowTable(config);

        table.acquire(key(1), 1L);
        table.acquire(key(2), 1L);
        table.acquire(key(3), 1L);
        assertEquals(3, table.size());

        // 将 flow1 关闭，使其成为优先回收对象。
        TcpFlow f1 = table.get(key(1));
        var rs = new com.github.guoyyit.networkidsjava.detect.RuleSet();
        f1.handle(Packets.c2s(1, 1, 1000, 0, TcpFlags.SYN, null), rs);
        f1.handle(Packets.of(2, 2, "10.1.0.1", 80, "10.0.0.1", 1001,
                5000, 1001, TcpFlags.SYN | TcpFlags.ACK, null), rs);
        f1.handle(Packets.c2s(3, 3, 1001, 5001, TcpFlags.ACK, null), rs);
        f1.handle(Packets.c2s(4, 4, 1001, 5001, TcpFlags.RST, null), rs);
        assertEquals(TcpState.CLOSED, f1.getState(Direction.FORWARD));

        FlowTable.AcquireResult result = table.acquire(key(4), 5L);
        assertNotNull(result.getFlow());
        assertTrue(result.getAnomalies().isEmpty());
        assertEquals(3, table.size());
        assertNull(table.get(key(1)));
        assertNotNull(table.get(key(4)));
    }

    @Test
    void fullTableWithNoEvictableReportsAnomaly() {
        IdsConfig config = new IdsConfig();
        config.setMaxFlows(2);
        // 让任何老化条件都不满足。
        config.setIdleTimeoutMillis(Long.MAX_VALUE);
        config.setZombieTimeoutMillis(Long.MAX_VALUE);
        config.setMaxFlowLifetimeMillis(Long.MAX_VALUE);
        FlowTable table = new FlowTable(config);

        table.acquire(key(1), 1L);
        table.acquire(key(2), 1L);
        FlowTable.AcquireResult result = table.acquire(key(3), 1L);
        assertNull(result.getFlow());
        assertEquals(1, result.getAnomalies().size());
        assertEquals(AnomalyType.FLOW_TABLE_FULL,
                result.getAnomalies().get(0).getType());
        assertEquals(2, table.size());
    }

    @Test
    void agingReclaimsIdleFlows() {
        IdsConfig config = new IdsConfig();
        config.setIdleTimeoutMillis(100L);
        FlowTable table = new FlowTable(config);
        table.acquire(key(1), 0L);
        assertTrue(table.tick(50L).isEmpty());
        assertEquals(1, table.tick(150L).size());
        assertEquals(0, table.size());
    }
}
