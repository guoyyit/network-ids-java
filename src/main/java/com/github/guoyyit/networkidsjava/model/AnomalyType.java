package com.github.guoyyit.networkidsjava.model;

/**
 * 畸形报文 / 非法状态迁移的分类。
 */
public enum AnomalyType {
    INVALID_FLAG_COMBINATION,
    ILLEGAL_STATE_TRANSITION,
    DATA_ON_NON_ESTABLISHED,
    DATA_AFTER_CLOSE,
    BAD_SEQUENCE,
    FLOW_TABLE_FULL,
    MALFORMED_PACKET
}
