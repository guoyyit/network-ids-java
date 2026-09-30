package com.github.guoyyit.networkidsjava.ids.alert;

import com.github.guoyyit.networkidsjava.ids.detect.MatchHit;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Windowed alert aggregation with immediate emission.
 *
 * <p>The first hit for an {@link AlertKey} opens a tumbling window and emits an
 * alert immediately with {@code hitCount=1}. Further hits inside the same
 * half-open window {@code [first, first+windowMs)} do not create new alerts:
 * the single alert is updated in place ({@code hitCount}, {@code lastTimestamp})
 * and the updated record is delivered again under the same deterministic
 * {@code alertId}; a durable consumer treats records with a known id as upserts.
 * A hit at or after {@code first+windowMs} closes the window and opens a new
 * window with a new alert.
 *
 * <p>Boundary semantics: window is half-open {@code [first, first+windowMs)};
 * a hit exactly at {@code first+windowMs} starts the next window.
 */
public final class AlertAggregator {

    private final long windowMs;
    private final Map<AlertKey, Window> windows = new LinkedHashMap<>();

    public AlertAggregator(long windowMs) {
        this.windowMs = windowMs;
    }

    public synchronized List<Alert> record(MatchHit hit, String connectionId,
                                           long timestamp) {
        AlertKey key = new AlertKey(connectionId, hit.rule().id(),
                hit.direction() == null ? "?" : hit.direction().name());
        List<Alert> changes = new ArrayList<>(2);
        Window window = windows.get(key);
        if (window != null && timestamp >= window.firstTimestamp + windowMs) {
            changes.add(window.toAlert());
            windows.remove(key);
            window = null;
        }
        if (window == null) {
            window = new Window(key, timestamp, hit);
            windows.put(key, window);
        } else {
            window.count++;
            window.lastTimestamp = timestamp;
        }
        window.deliveredCurrent = false;
        changes.add(window.toAlert());
        window.deliveredCurrent = true;
        return changes;
    }

    /** Flush windows whose latest aggregate has not been delivered yet. */
    public synchronized List<Alert> flushAll() {
        return flush(true);
    }

    /** Force final delivery of every open window (used on shutdown). */
    public synchronized List<Alert> forceFlushAll() {
        return flush(false);
    }

    public synchronized List<Alert> flush(String connectionId) {
        List<Alert> emitted = new ArrayList<>();
        windows.entrySet().removeIf(entry -> {
            if (entry.getKey().connectionId().equals(connectionId)) {
                Window window = entry.getValue();
                if (!window.deliveredCurrent) {
                    emitted.add(window.toAlert());
                }
                return true;
            }
            return false;
        });
        return emitted;
    }

    public synchronized int activeWindows() {
        return windows.size();
    }

    private List<Alert> flush(boolean onlyUndelivered) {
        List<Alert> emitted = new ArrayList<>(windows.size());
        for (Window window : windows.values()) {
            if (!onlyUndelivered || !window.deliveredCurrent) {
                emitted.add(window.toAlert());
                window.deliveredCurrent = true;
            }
        }
        windows.clear();
        return emitted;
    }

    private static final class Window {
        private final AlertKey key;
        private final long firstTimestamp;
        private final long firstOffset;
        private final byte[] firstContext;
        private long lastTimestamp;
        private long count = 1;
        private boolean deliveredCurrent;

        private Window(AlertKey key, long timestamp, MatchHit firstHit) {
            this.key = key;
            this.firstTimestamp = timestamp;
            this.lastTimestamp = timestamp;
            this.firstOffset = firstHit.offset();
            this.firstContext = firstHit.context();
        }

        private Alert toAlert() {
            String alertId = key.connectionId() + "|" + key.ruleId()
                    + "|" + key.direction() + "|" + firstTimestamp;
            String contextHex = HexFormat.of().formatHex(firstContext);
            return new Alert(alertId, key.connectionId(), key.ruleId(),
                    firstTimestamp, lastTimestamp, count,
                    key.direction(), firstOffset, contextHex);
        }
    }
}
