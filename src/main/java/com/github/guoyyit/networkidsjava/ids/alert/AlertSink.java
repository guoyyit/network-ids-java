package com.github.guoyyit.networkidsjava.ids.alert;

import java.util.List;

/**
 * Recipient of committed alerts.
 */
public interface AlertSink {

    void emit(Alert alert);

    default void emitAll(List<Alert> alerts) {
        alerts.forEach(this::emit);
    }
}
