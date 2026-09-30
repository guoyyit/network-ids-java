package com.github.guoyyit.networkidsjava.engine;

import com.github.guoyyit.networkidsjava.alert.Alert;
import com.github.guoyyit.networkidsjava.model.AnomalyEvent;
import com.github.guoyyit.networkidsjava.model.Direction;

import java.util.ArrayList;
import java.util.List;

/**
 * 单个报文经过某条流处理后的产出：新连续重组数据、告警、异常。
 */
public final class FlowResult {
    private final List<ReassembledChunk> chunks = new ArrayList<>();
    private final List<Alert> alerts = new ArrayList<>();
    private final List<AnomalyEvent> anomalies = new ArrayList<>();

    public List<ReassembledChunk> getChunks() {
        return chunks;
    }

    public List<Alert> getAlerts() {
        return alerts;
    }

    public List<AnomalyEvent> getAnomalies() {
        return anomalies;
    }

    /** 某方向上新变为连续可交付的一段重组数据。 */
    public static final class ReassembledChunk {
        private final Direction direction;
        private final long streamOffset;
        private final byte[] data;

        public ReassembledChunk(Direction direction, long streamOffset, byte[] data) {
            this.direction = direction;
            this.streamOffset = streamOffset;
            this.data = data == null ? new byte[0] : data.clone();
        }

        public Direction getDirection() {
            return direction;
        }

        public long getStreamOffset() {
            return streamOffset;
        }

        public byte[] getData() {
            return data.clone();
        }

        public int length() {
            return data.length;
        }
    }
}
