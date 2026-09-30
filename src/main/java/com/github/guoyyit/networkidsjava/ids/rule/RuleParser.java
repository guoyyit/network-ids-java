package com.github.guoyyit.networkidsjava.ids.rule;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses textual rule definitions, one rule per line.
 *
 * <p>Syntax:
 * <pre>
 * # comment line
 * &lt;ruleId&gt;: hex|&lt;hex bytes with optional spaces&gt;
 * &lt;ruleId&gt;: ascii|&lt;literal content&gt;
 * </pre>
 * Inline {@code #} comments are supported. Duplicate ids within one parse are
 * rejected with {@link RuleParseException}.
 */
public final class RuleParser {

    private RuleParser() {
    }

    public static Rule parseLine(String line) {
        String stripped = stripComment(line).trim();
        if (stripped.isEmpty()) {
            return null;
        }
        int colon = stripped.indexOf(':');
        if (colon <= 0) {
            throw new RuleParseException("rule must be '<id>: <content>': " + line);
        }
        String id = stripped.substring(0, colon).trim();
        String body = stripped.substring(colon + 1).trim();
        byte[] content;
        if (body.startsWith("ascii|")) {
            content = body.substring("ascii|".length())
                    .getBytes(StandardCharsets.UTF_8);
        } else if (body.startsWith("hex|")) {
            content = decodeHex(body.substring("hex|".length())
                    .replaceAll("\\s+", ""));
        } else {
            content = decodeHex(body.replaceAll("\\s+", ""));
        }
        return new Rule(id, content);
    }

    public static List<Rule> parse(String text) {
        List<Rule> rules = new ArrayList<>();
        java.util.Set<String> ids = new java.util.HashSet<>();
        for (String line : text.split("\\R", -1)) {
            Rule rule = parseLine(line);
            if (rule != null) {
                if (!ids.add(rule.id())) {
                    throw new RuleParseException("duplicate rule id: " + rule.id());
                }
                rules.add(rule);
            }
        }
        return List.copyOf(rules);
    }

    private static String stripComment(String line) {
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            } else if (c == '#' && !quoted) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static byte[] decodeHex(String hex) {
        if (hex.isEmpty() || hex.length() % 2 != 0) {
            throw new RuleParseException(
                    "hex content must have an even number of digits: " + hex);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(hex.length() / 2);
        for (int i = 0; i < hex.length(); i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high < 0 || low < 0) {
                throw new RuleParseException("invalid hex digit in: " + hex);
            }
            out.write((high << 4) | low);
        }
        return out.toByteArray();
    }
}
