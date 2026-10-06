package com.github.guoyyit.networkidsjava.engine;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.alert.AggregatedAlert;
import com.github.guoyyit.networkidsjava.model.AnomalyEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * 引擎处理单个报文后的全部产出。
 */
public final class ProcessResult {
    private final List<AggregatedAlert> aggregatedAlerts = new ArrayList<>();
    private final List<Alert> alerts = new ArrayList<>();
    private final List<AnomalyEvent> anomalies = new ArrayList<>();
    private final List<FlowResult.ReassembledChunk> chunks = new ArrayList<>();

    public List<AggregatedAlert> getAggregatedAlerts() {
        return aggregatedAlerts;
    }

    public List<Alert> getAlerts() {
        return alerts;
    }

    public List<AnomalyEvent> getAnomalies() {
        return anomalies;
    }

    /**
     * 本报文处理过程中新交付的重组数据块：既包括本报文所属连接
     * 正常交付的数据，也包括因回收收尾而被排空检测的在途数据。
     */
    public List<FlowResult.ReassembledChunk> getChunks() {
        return chunks;
    }
}
