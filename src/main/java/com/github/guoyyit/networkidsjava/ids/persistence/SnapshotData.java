package com.github.guoyyit.networkidsjava.ids.persistence;

import com.github.guoyyit.networkidsjava.ids.rule.Rule;

import java.util.List;

/**
 * Full durable snapshot: rule set and all live flows.
 */
public record SnapshotData(long position, List<Rule> rules, List<FlowSnapshot> flows) {
}
