package com.github.guoyyit.networkidsjava.ids.engine;

/**
 * All engine configuration knobs. Every field is documented in README_IDS.md.
 */
public record IdsConfig(int maxFlows,
                        long idleTimeoutMs,
                        long closedTimeoutMs,
                        long maxBufferedBytesPerDirection,
                        long aggregationWindowMs,
                        int contextRadius,
                        long snapshotInterval,
                        String checkpointDir,
                        boolean persistenceEnabled) {

    public static IdsConfig defaults() {
        return new IdsConfig(10_000, 600_000L, 30_000L,
                1_048_576L, 60_000L, 32, 1024L, "data/ids", true);
    }
}
