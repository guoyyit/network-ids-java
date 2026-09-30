package com.github.guoyyit.networkidsjava.ids.persistence;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;

import java.util.List;

/**
 * One atomic commit: all alerts produced by packets up to {@code position}
 * inclusive are persisted together with the position.
 */
public record CommitRecord(long position, List<Alert> alerts) {
}
