package com.github.guoyyit.networkidsjava.detect;

import com.github.guoyyit.networkidsjava.model.Direction;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 规则集合：copy-on-write 快照。读路径(检测)无锁，热更新通过原子替换快照生效，
 * 正在使用旧快照的检测仍完成，不会中断检测或漏检。
 */
public final class RuleSet {
    private volatile Map<String, Rule> rules;
    private volatile long version;

    public RuleSet() {
        this.rules = Collections.emptyMap();
        this.version = 0L;
    }

    /** 原子替换为新快照。 */
    public synchronized void replaceAll(List<Rule> newRules) {
        rules = ordered(newRules);
        version++;
    }

    public synchronized void addOrUpdate(Rule rule) {
        Map<String, Rule> next = new LinkedHashMap<>(rules);
        next.put(rule.getId(), rule);
        rules = Collections.unmodifiableMap(next);
        version++;
    }

    public synchronized boolean remove(String ruleId) {
        if (!rules.containsKey(ruleId)) {
            return false;
        }
        Map<String, Rule> next = new LinkedHashMap<>(rules);
        next.remove(ruleId);
        rules = Collections.unmodifiableMap(next);
        version++;
        return true;
    }

    /** 返回当前不可变快照(检测中安全遍历)。 */
    public List<Rule> snapshot() {
        return List.copyOf(rules.values());
    }

    public Rule get(String ruleId) {
        return rules.get(ruleId);
    }

    public long getVersion() {
        return version;
    }

    /** 供持久化: 序列化当前规则为文本行。 */
    public List<String> toLines() {
        List<String> lines = new ArrayList<>();
        for (Rule rule : rules.values()) {
            lines.add(toLine(rule));
        }
        return lines;
    }

    /** 与 RuleParser 对应的规范文本形式。 */
    public static String toLine(Rule rule) {
        StringBuilder sb = new StringBuilder();
        sb.append(rule.getId()).append(':');
        Direction direction = rule.getDirection();
        if (direction != null) {
            sb.append(" direction:").append(direction.name().toLowerCase()).append(';');
        }
        sb.append(" content:");
        appendContent(sb, rule.rawContent());
        if (rule.isCaseInsensitive()) {
            sb.append(" nocase;");
        }
        if (rule.getMessage() != null) {
            sb.append(" message:").append(rule.getMessage()).append(';');
        }
        return sb.toString();
    }

    private static void appendContent(StringBuilder sb, byte[] content) {
        boolean printable = true;
        for (byte b : content) {
            if (b < 0x20 || b == 0x7F || b == '|') {
                printable = false;
                break;
            }
        }
        if (printable) {
            sb.append(new String(content, java.nio.charset.StandardCharsets.UTF_8));
        } else {
            sb.append('|');
            for (byte b : content) {
                sb.append(String.format("%02X ", b & 0xFF));
            }
            if (content.length > 0) {
                sb.setLength(sb.length() - 1);
            }
            sb.append('|');
        }
    }

    private static Map<String, Rule> ordered(List<Rule> list) {
        Map<String, Rule> map = new LinkedHashMap<>();
        for (Rule rule : list) {
            map.put(rule.getId(), rule);
        }
        return Collections.unmodifiableMap(map);
    }
}
