package com.github.guoyyit.networkidsjava.ids.source;

import com.github.guoyyit.networkidsjava.ids.model.Packet;

import java.util.List;

/**
 * A replayable source of captured packets. {@code loadAll} returns the exact
 * same sequence on every run, which is the basis of reproducible detection.
 */
public interface PacketSource {

    List<Packet> loadAll();
}
