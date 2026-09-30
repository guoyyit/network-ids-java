package com.github.guoyyit.networkidsjava.ids.source;

import com.github.guoyyit.networkidsjava.ids.model.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Bounded in-memory pipe injecting packets from a local loopback / memory
 * channel. The pipe retains all injected packets so a crashed consumer can
 * resume from the last committed position.
 *
 * <p>Injection is synchronous: {@link #inject(Packet, Consumer)} assigns the
 * global capture position, stores the packet and invokes the consumer before
 * returning, which gives a happens-before edge between persistence and the
 * acknowledgement.
 */
public final class InMemoryPacketPipe implements PacketSource {

    private final List<Packet> packets = new ArrayList<>();

    public InMemoryPacketPipe() {
    }

    public synchronized void inject(Packet packet, Consumer<Packet> consumer) {
        Packet positioned = store(packet);
        consumer.accept(positioned);
    }

    public synchronized Packet inject(Packet packet) {
        return store(packet);
    }

    public synchronized long size() {
        return packets.size();
    }

    @Override
    public synchronized List<Packet> loadAll() {
        return List.copyOf(packets);
    }

    private Packet store(Packet packet) {
        long position = packets.size();
        Packet positioned = packet.position() >= 0 ? packet : packet.withPosition(position);
        packets.add(positioned);
        return positioned;
    }
}
