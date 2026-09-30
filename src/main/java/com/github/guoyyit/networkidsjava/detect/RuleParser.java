package com.github.guoyyit.networkidsjava.detect;

import com.github.guoyyit.networkidsjava.model.Direction;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 规则文本解析。语法(详见 README):
 * <pre>
 *   &lt;ruleId&gt;: [direction &lt;forward|reverse|both&gt;;] content:&lt;字符串 或 |十六进制|&gt; [nocase] [message:&lt;说明&gt;]
 * </pre>
 */
public final class RuleParser {

    private RuleParser() {
    }

    public static Rule parse(String line) {
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            return null;
        }
        int colon = trimmed.indexOf(':');
        if (colon <= 0) {
            throw new IllegalArgumentException("规则缺少 id: " + line);
        }
        String id = trimmed.substring(0, colon).trim();
        Map<String, String> fields = splitFields(trimmed.substring(colon + 1));

        String contentRaw = fields.get("content");
        if (contentRaw == null) {
            throw new IllegalArgumentException("规则缺少 content: " + line);
        }
        byte[] content = decodeContent(contentRaw.trim());
        if (content.length == 0) {
            throw new IllegalArgumentException("规则 content 不能为空: " + line);
        }
        boolean nocase = fields.containsKey("nocase");
        Direction direction = null;
        String dirValue = fields.get("direction");
        if (dirValue != null) {
            direction = parseDirection(dirValue.trim());
        }
        String message = fields.getOrDefault("message", id);
        return new Rule(id, message, direction, content, nocase);
    }

    public static List<Rule> parseAll(Iterable<String> lines) {
        List<Rule> rules = new ArrayList<>();
        for (String line : lines) {
            Rule rule = parse(line);
            if (rule != null) {
                rules.add(rule);
            }
        }
        return rules;
    }

    /** content 支持 |AA BB| 十六进制或普通字符串；二者可混用，如 "GET |2F|"。 */
    static byte[] decodeContent(String raw) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int i = 0;
        while (i < raw.length()) {
            char c = raw.charAt(i);
            if (c == '|') {
                int end = raw.indexOf('|', i + 1);
                if (end < 0) {
                    throw new IllegalArgumentException("十六进制内容缺少闭合 |: " + raw);
                }
                out.writeBytes(decodeHex(raw.substring(i + 1, end)));
                i = end + 1;
            } else {
                byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                out.writeBytes(b);
                i++;
            }
        }
        return out.toByteArray();
    }

    /** 将 "AA BB" 形式的十六进制解码为字节，允许无空格连续书写。 */
    static byte[] decodeHex(String hex) {
        String compact = hex.replaceAll("\\s+", "");
        if (compact.length() % 2 != 0) {
            throw new IllegalArgumentException("非法十六进制(奇数位): " + hex);
        }
        byte[] result = new byte[compact.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int high = Character.digit(compact.charAt(i * 2), 16);
            int low = Character.digit(compact.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("非法十六进制数字: " + hex);
            }
            result[i] = (byte) ((high << 4) | low);
        }
        return result;
    }

    static Direction parseDirection(String value) {
        return switch (value.toLowerCase()) {
            case "forward", "fwd", "c2s" -> Direction.FORWARD;
            case "reverse", "rev", "s2c" -> Direction.REVERSE;
            case "both", "any" -> null;
            default -> throw new IllegalArgumentException("非法 direction: " + value);
        };
    }

    /** 按 "key:value;" 切分；content 的值中允许出现 | 但不允许出现裸 ';'。 */
    private static Map<String, String> splitFields(String body) {
        Map<String, String> fields = new LinkedHashMap<>();
        int i = 0;
        while (i < body.length()) {
            int nextSemi = body.indexOf(';', i);
            int nextColon = body.indexOf(':', i);
            if (nextColon < 0 || (nextSemi >= 0 && nextSemi < nextColon)) {
                // 到下一个分号为止没有冒号：视为布尔标志。
                String token = (nextSemi < 0 ? body.substring(i) : body.substring(i, nextSemi)).trim();
                if (!token.isEmpty()) {
                    fields.put(token, "");
                }
                i = nextSemi < 0 ? body.length() : nextSemi + 1;
                continue;
            }
            int colon = nextColon;
            String key = body.substring(i, colon).trim();
            int semi = body.indexOf(';', colon + 1);
            String value;
            if (semi < 0) {
                value = body.substring(colon + 1);
                i = body.length();
            } else {
                value = body.substring(colon + 1, semi);
                i = semi + 1;
            }
            if (key.isEmpty()) {
                continue;
            }
            // 无值的布尔标志(如 nocase)以 key 本身存放。
            fields.put(key, value);
        }
        return fields;
    }
}
