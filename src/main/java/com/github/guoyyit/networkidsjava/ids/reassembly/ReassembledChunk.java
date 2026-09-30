package com.github.guoyyit.networkidsjava.ids.reassembly;

/**
 * A contiguous chunk of reassembled stream data for one direction.
 *
 * @param completionTimestamp capture timestamp of the segment providing the
 *                            chunk's final byte; used for deterministic match
 *                            timestamps under out-of-order delivery
 */
public record ReassembledChunk(long startSeq, long completionTimestamp, byte[] data) {

    public ReassembledChunk(long startSeq, long completionTimestamp, byte[] data) {
        this.startSeq = startSeq;
        this.completionTimestamp = completionTimestamp;
        this.data = data == null ? new byte[0] : data.clone();
    }

    @Override
    public byte[] data() {
        return data.clone();
    }
}
