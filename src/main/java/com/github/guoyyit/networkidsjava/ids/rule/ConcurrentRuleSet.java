package com.github.guoyyit.networkidsjava.ids.rule;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Live rule set supporting dynamic add/remove. Readers always observe a
 * consistent immutable snapshot; updates never interrupt in-flight detection.
 *
 * <p>A detection pass that started before an update keeps using the old
 * snapshot until the pass completes; new passes observe the new set. In-flight
 * matches are therefore never lost or corrupted by a concurrent update.
 */
public final class ConcurrentRuleSet {

    private volatile List<Rule> snapshot;

    public ConcurrentRuleSet() {
        this.snapshot = List.of();
    }

    public ConcurrentRuleSet(List<Rule> initial) {
        replaceAll(initial);
    }

    public List<Rule> snapshot() {
        return snapshot;
    }

    public synchronized void add(Rule rule) {
        Map<String, Rule> byId = toMap(snapshot);
        byId.put(rule.id(), rule);
        snapshot = List.copyOf(byId.values());
    }

    public synchronized boolean remove(String ruleId) {
        Map<String, Rule> byId = toMap(snapshot);
        boolean removed = byId.remove(ruleId) != null;
        if (removed) {
            snapshot = List.copyOf(byId.values());
        }
        return removed;
    }

    public synchronized void replaceAll(List<Rule> rules) {
        snapshot = List.copyOf(toMap(rules).values());
    }

    private static Map<String, Rule> toMap(List<Rule> rules) {
        Map<String, Rule> byId = new LinkedHashMap<>();
        for (Rule rule : rules) {
            if (byId.put(rule.id(), rule) != null) {
                throw new RuleParseException("duplicate rule id: " + rule.id());
            }
        }
        return new LinkedHashMap<>(byId);
    }
}
