package com.github.guoyyit.networkidsjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Spring binding for ids.* configuration properties.
 */
@ConfigurationProperties(prefix = "ids")
public class IdsProperties {

    private int maxFlows = 10000;
    private long idleTimeoutMs = 600_000L;
    private long closedTimeoutMs = 30_000L;
    private long maxBufferedBytesPerDirection = 1_048_576L;
    private long aggregationWindowMs = 60_000L;
    private int contextRadius = 32;
    private long snapshotInterval = 1024L;
    private String checkpointDir = "data/ids";
    private boolean persistenceEnabled = true;

    public int getMaxFlows() {
        return maxFlows;
    }

    public void setMaxFlows(int maxFlows) {
        this.maxFlows = maxFlows;
    }

    public long getIdleTimeoutMs() {
        return idleTimeoutMs;
    }

    public void setIdleTimeoutMs(long idleTimeoutMs) {
        this.idleTimeoutMs = idleTimeoutMs;
    }

    public long getClosedTimeoutMs() {
        return closedTimeoutMs;
    }

    public void setClosedTimeoutMs(long closedTimeoutMs) {
        this.closedTimeoutMs = closedTimeoutMs;
    }

    public long getMaxBufferedBytesPerDirection() {
        return maxBufferedBytesPerDirection;
    }

    public void setMaxBufferedBytesPerDirection(long maxBufferedBytesPerDirection) {
        this.maxBufferedBytesPerDirection = maxBufferedBytesPerDirection;
    }

    public long getAggregationWindowMs() {
        return aggregationWindowMs;
    }

    public void setAggregationWindowMs(long aggregationWindowMs) {
        this.aggregationWindowMs = aggregationWindowMs;
    }

    public int getContextRadius() {
        return contextRadius;
    }

    public void setContextRadius(int contextRadius) {
        this.contextRadius = contextRadius;
    }

    public long getSnapshotInterval() {
        return snapshotInterval;
    }

    public void setSnapshotInterval(long snapshotInterval) {
        this.snapshotInterval = snapshotInterval;
    }

    public String getCheckpointDir() {
        return checkpointDir;
    }

    public void setCheckpointDir(String checkpointDir) {
        this.checkpointDir = checkpointDir;
    }

    public boolean isPersistenceEnabled() {
        return persistenceEnabled;
    }

    public void setPersistenceEnabled(boolean persistenceEnabled) {
        this.persistenceEnabled = persistenceEnabled;
    }
}
