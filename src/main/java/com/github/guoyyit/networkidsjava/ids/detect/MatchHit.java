package com.github.guoyyit.networkidsjava.ids.detect;

import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import com.github.guoyyit.networkidsjava.ids.tcp.Direction;

/**
 * One content match in a reassembled stream. Offsets are absolute byte offsets
 * from the start of that direction's stream.
 */
public record MatchHit(Rule rule, Direction direction, long offset, byte[] context) {

    @Override
    public byte[] context() {
        return context == null ? new byte[0] : context.clone();
    }
}
