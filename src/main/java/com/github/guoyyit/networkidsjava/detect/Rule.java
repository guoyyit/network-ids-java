package com.github.guoyyit.networkidsjava.detect;

import com.github.guoyyit.networkidsjava.model.Direction;

/**
 * 一条检测规则(不可见)。
 *
 * <p>最小规则语法: {@code <id>: <content 或 |hex|> [nocase] [-> <message>]},
 * 完整语法见 RuleParser 与文档。
 */
public final class Rule {
    private final String id;
    private final String message;
    private final Direction direction;
    private final byte[] content;
    private final boolean caseInsensitive;

    public Rule(String id, String message, Direction direction,
                byte[] content, boolean caseInsensitive) {
        this.id = id;
        this.message = message;
        this.direction = direction;
        this.content = content == null ? new byte[0] : content.clone();
        this.caseInsensitive = caseInsensitive;
    }

    public String getId() {
        return id;
    }

    public String getMessage() {
        return message;
    }

    /** null 表示双向匹配。 */
    public Direction getDirection() {
        return direction;
    }

    public byte[] getContent() {
        return content.clone();
    }

    public boolean isCaseInsensitive() {
        return caseInsensitive;
    }

    @Override
    public String toString() {
        return "Rule{" + id + ", '" + message + "'}";
    }

    public int contentLength() {
        return content.length;
    }

    public byte[] rawContent() {
        return content.clone();
    }
}
