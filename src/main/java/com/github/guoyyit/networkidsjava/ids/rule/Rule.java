package com.github.guoyyit.networkidsjava.ids.rule;

import java.util.List;

/**
 * Detection rule.
 *
 * <p>Rule syntax: {@code <id>: <hex-content>} where content is an even-length
 * hexadecimal string, optionally containing spaces between byte groups.
 * Lines starting with {@code #} are comments.
 */
public record Rule(String id, byte[] content) {

    public Rule {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("rule id must not be blank");
        }
        if (content == null || content.length == 0) {
            throw new IllegalArgumentException("rule content must not be empty");
        }
        content = content.clone();
    }

    @Override
    public byte[] content() {
        return content.clone();
    }
}
