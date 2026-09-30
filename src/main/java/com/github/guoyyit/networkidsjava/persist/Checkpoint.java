package com.github.guoyyit.networkidsjava.persist;

import java.util.ArrayList;
import java.util.List;

/**
 * 一次提交点：已处理到的位置、该位置已提交的规则快照版本与规则文本。
 */
public final class Checkpoint {
    private final long lastProcessedOrder;
    private final long ruleVersion;
    private final List<String> ruleLines;

    public Checkpoint(long lastProcessedOrder, long ruleVersion, List<String> ruleLines) {
        this.lastProcessedOrder = lastProcessedOrder;
        this.ruleVersion = ruleVersion;
        this.ruleLines = ruleLines == null ? new ArrayList<>() : new ArrayList<>(ruleLines);
    }

    public long getLastProcessedOrder() {
        return lastProcessedOrder;
    }

    public long getRuleVersion() {
        return ruleVersion;
    }

    public List<String> getRuleLines() {
        return new ArrayList<>(ruleLines);
    }
}
