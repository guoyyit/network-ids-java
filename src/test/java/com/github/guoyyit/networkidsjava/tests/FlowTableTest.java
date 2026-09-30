package com.github.guoyyit.networkidsjava.tests;

import com.github.guoyyit.networkidsjava.ids.flow.FlowTable;
import com.github.guoyyit.networkidsjava.ids.flow.TcpFlow;
import com.github.guoyyit.networkidsjava.ids.model.FlowKey;
import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.model.TcpFlags;
import com.github.guoyyit.networkidsjava.ids.tcp.TcpState;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class FlowTableTest {

    private static FlowKey key(int n) {
        return new FlowKey("10.0.0." + n, 1000 + n, "10.0.1.1", 80);
    }

    private static TcpFlow establish(FlowTable table, FlowKey key, long ts) {
        TcpFlow flow = table.getOrCreate(key, ts, 4096);
        Packet syn = new Packet(ts, "10.0.0.1", 1000, "10.0.1.1", 80,
                1, 0, TcpFlags.SYN, new byte[0]);
        flow.handlePacket(syn);
        Packet synAck = new Packet(ts, "10.0.1.1", 80, "10.0.0.1", 1000,
                1, 0, TcpFlags.SYN | TcpFlags.ACK, new byte[0]);
        flow.handlePacket(synAck);
        Packet ack = new Packet(ts, "10.0.0.1", 1000, "10.0.1.1", 80,
                1, 0, TcpFlags.ACK, new byte[0]);
        flow.handlePacket(ack);
        return flow;
    }

    @Test
    void idleFlowsAreReclaimed() {
        FlowTable table = new FlowTable(10, 1000, 100);
        establish(table, key(1), 0);
        List<TcpFlow> evicted = new ArrayList<>();
        table.evictExpired(999, evicted::add);
        assertEquals(1, table.size());
        table.evictExpired(1000, evicted::add);
        assertEquals(0, table.size());
        assertEquals(1, evicted.size());
    }

    @Test
    void closedFlowsExpireAfterShortTimeout() {
        FlowTable table = new FlowTable(10, 10_000, 100);
        TcpFlow flow = establish(table, key(1), 0);
        flow.handlePacket(new Packet(1, "10.0.0.1", 1000, "10.0.1.1", 80,
                1, 0, TcpFlags.RST | TcpFlags.ACK, new byte[0]));
        assertEquals(TcpState.CLOSED, flow.state());

        List<TcpFlow> evicted = new ArrayList<>();
        table.evictExpired(101, evicted::add);
        assertEquals(0, table.size());
        assertEquals(1, evicted.size());
    }

    @Test
    void oldestFlowIsEvictedWhenCapacityReached() {
        FlowTable table = new FlowTable(2, 100_000, 100_000);
        TcpFlow first = establish(table, key(1), 10);
        establish(table, key(2), 20);
        List<TcpFlow> evicted = new ArrayList<>();
        TcpFlow removed = table.evictOldest(30, evicted::add);
        assertSame(first, removed);
        assertEquals(1, evicted.size());
        assertEquals(1, table.size());

        TcpFlow third = table.getOrCreate(key(3), 30, 4096);
        assertEquals(2, table.size());
        assertSame(third, table.get(key(3)));
    }

    @Test
    void touchKeepsFlowActive() {
        FlowTable table = new FlowTable(10, 1000, 100);
        establish(table, key(1), 0);
        table.evictExpired(500, f -> { });
        table.touch(table.get(key(1)), 900);
        List<TcpFlow> evicted = new ArrayList<>();
        table.evictExpired(1000, evicted::add);
        assertEquals(1, table.size());
        table.evictExpired(1900, evicted::add);
        assertEquals(0, table.size());
    }
}
