package com.github.guoyyit.networkidsjava.config;

/**
 * 引擎全部可配置项。使用构建器/构造默认值，详见 README。
 */
public final class IdsConfig {
    private int maxFlows = 10_000;
    private long idleTimeoutMillis = 300_000L;
    private long zombieTimeoutMillis = 600_000L;
    private long timeWaitMillis = 120_000L;
    private long maxFlowLifetimeMillis = 3_600_000L;
    private int maxReassemblyFragmentsPerFlow = 10_000;
    private long alertWindowMillis = 60_000L;
    private long commitEveryNPackets = 100L;
    private int maxCommittedRetain = 100_000;
    private String stateDir = "ids-state";

    public IdsConfig() {
    }

    public int getMaxFlows() {
        return maxFlows;
    }

    public void setMaxFlows(int maxFlows) {
        this.maxFlows = maxFlows;
    }

    public long getIdleTimeoutMillis() {
        return idleTimeoutMillis;
    }

    public void setIdleTimeoutMillis(long idleTimeoutMillis) {
        this.idleTimeoutMillis = idleTimeoutMillis;
    }

    public long getZombieTimeoutMillis() {
        return zombieTimeoutMillis;
    }

    public void setZombieTimeoutMillis(long zombieTimeoutMillis) {
        this.zombieTimeoutMillis = zombieTimeoutMillis;
    }

    public long getTimeWaitMillis() {
        return timeWaitMillis;
    }

    public void setTimeWaitMillis(long timeWaitMillis) {
        this.timeWaitMillis = timeWaitMillis;
    }

    public long getMaxFlowLifetimeMillis() {
        return maxFlowLifetimeMillis;
    }

    public void setMaxFlowLifetimeMillis(long maxFlowLifetimeMillis) {
        this.maxFlowLifetimeMillis = maxFlowLifetimeMillis;
    }

    public int getMaxReassemblyFragmentsPerFlow() {
        return maxReassemblyFragmentsPerFlow;
    }

    public void setMaxReassemblyFragmentsPerFlow(int maxReassemblyFragmentsPerFlow) {
        this.maxReassemblyFragmentsPerFlow = maxReassemblyFragmentsPerFlow;
    }

    public long getAlertWindowMillis() {
        return alertWindowMillis;
    }

    public void setAlertWindowMillis(long alertWindowMillis) {
        this.alertWindowMillis = alertWindowMillis;
    }

    public long getCommitEveryNPackets() {
        return commitEveryNPackets;
    }

    public void setCommitEveryNPackets(long commitEveryNPackets) {
        this.commitEveryNPackets = commitEveryNPackets;
    }

    public int getMaxCommittedRetain() {
        return maxCommittedRetain;
    }

    public void setMaxCommittedRetain(int maxCommittedRetain) {
        this.maxCommittedRetain = maxCommittedRetain;
    }

    public String getStateDir() {
        return stateDir;
    }

    public void setStateDir(String stateDir) {
        this.stateDir = stateDir;
    }
}
