package com.github.guoyyit.networkidsjava.ids.alert;

import java.util.Objects;

/**
 * Aggregation identity: same connection incarnation + same rule + same direction
 * aggregate into one alert within the window.
 */
public final class AlertKey {

    private final String connectionId;
    private final String ruleId;
    private final String direction;

    public AlertKey(String connectionId, String ruleId, String direction) {
        this.connectionId = connectionId;
        this.ruleId = ruleId;
        this.direction = direction;
    }

    public String connectionId() {
        return connectionId;
    }

    public String ruleId() {
        return ruleId;
    }

    public String direction() {
        return direction;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AlertKey other)) {
            return false;
        }
        return Objects.equals(connectionId, other.connectionId)
                && Objects.equals(ruleId, other.ruleId)
                && Objects.equals(direction, other.direction);
    }

    @Override
    public int hashCode() {
        return Objects.hash(connectionId, ruleId, direction);
    }
}
