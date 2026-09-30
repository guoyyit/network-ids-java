package com.github.guoyyit.networkidsjava.ids.source;

import com.github.guoyyit.networkidsjava.ids.model.Packet;

import java.util.ArrayList;
import java.util.List;

/**
 * In-memory packet source used by tests and fixed-file replay.
 */
public final class ListPacketSource implements PacketSource {

    private final List<Packet> packets = new ArrayList<>();

    public ListPacketSource() {
    }

    public ListPacketSource(List<Packet> packets) {
        addAll(packets);
    }

    public synchronized void add(Packet packet) {
        long position = packets.size();
        packets.add(packet.position() < 0 ? packet.withPosition(position) : packet);
    }

    public synchronized void addAll(List<Packet> more) {
        more.forEach(this::add);
    }

    @Override
    public synchronized List<Packet> loadAll() {
        return List.copyOf(packets);
    }
}
