package com.github.guoyyit.networkidsjava.engine;

import java.util.TreeMap;

/**
 * 单方向 TCP 载荷重组器。
 *
 * <p>重叠规则(确定可复现): <b>序列号较小者优先(lowest-SEQ-wins)</b>。
 * 即重组结果始终与报文严格按序到达时一致；同一字节若被两个段覆盖，
 * 取覆盖该字节的、起始序列号最小的段中的内容。乱序、重复、重叠都由此统一处理。
 */
public final class StreamReassembler {

    private final TreeMap<Long, byte[]> fragments = new TreeMap<>();
    private long nextOffset;
    private int totalBufferedBytes;
    private boolean closed;

    public StreamReassembler(long initialOffset) {
        this.nextOffset = initialOffset;
    }

    /**
     * 插入一个段。
     *
     * @param seq     段首字节的绝对序列号
     * @param payload 段载荷
     * @return 当前已变为连续(offset==nextOffset)的全部新字节；无新数据返回空数组
     */
    public byte[] insert(long seq, byte[] payload) {
        if (closed || payload == null || payload.length == 0) {
            return new byte[0];
        }
        long start = seq;
        int dataOffset = 0;
        int length = payload.length;

        // 已交付(低于 nextOffset)的部分整体忽略——这正是重复报文的处理。
        if (start < nextOffset) {
            long overlap = nextOffset - start;
            if (overlap >= length) {
                return new byte[0];
            }
            dataOffset = (int) overlap;
            start = nextOffset;
            length -= (int) overlap;
        }

        // 序列号较小者优先：删除与本段重叠的既有(序列号更大的)片段，
        // 同时裁掉本段中已被更小序列号片段覆盖的前缀，保证每个字节只保留一份。
        long newEnd = start + length;
        var head = fragments.floorKey(start);
        if (head != null) {
            byte[] headData = fragments.get(head);
            long headEnd = head + headData.length;
            if (headEnd >= newEnd && head < start) {
                // 完全被更小序列号的既有片段覆盖。
                return new byte[0];
            }
            if (head < start && headEnd > start) {
                int cut = (int) (headEnd - start);
                dataOffset += cut;
                start += cut;
                length -= cut;
            }
        }
        var tailIt = fragments.tailMap(start, false).entrySet().iterator();
        while (tailIt.hasNext()) {
            var e = tailIt.next();
            long tStart = e.getKey();
            long tEnd = tStart + e.getValue().length;
            if (tStart >= newEnd || length <= 0) {
                break;
            }
            totalBufferedBytes -= e.getValue().length;
            tailIt.remove();
            if (tEnd > newEnd) {
                // 既有片段尾部超出本段：序列号更大的尾部保留。
                int keepOffset = (int) (newEnd - tStart);
                byte[] kept = java.util.Arrays.copyOfRange(e.getValue(), keepOffset, e.getValue().length);
                fragments.put(newEnd, kept);
                totalBufferedBytes += kept.length;
            }
        }

        byte[] keptData = java.util.Arrays.copyOfRange(payload, dataOffset, dataOffset + length);
        fragments.put(start, keptData);
        totalBufferedBytes += keptData.length;

        return drainContiguous();
    }

    /** 从 nextOffset 起取出所有连续片段并拼接交付。 */
    private byte[] drainContiguous() {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        Long cur = fragments.ceilingKey(nextOffset);
        while (cur != null && cur == nextOffset) {
            byte[] data = fragments.remove(cur);
            totalBufferedBytes -= data.length;
            out.writeBytes(data);
            nextOffset += data.length;
            cur = fragments.ceilingKey(nextOffset);
        }
        return out.toByteArray();
    }

    /** 当前等待中的首个空洞偏移(=已连续交付长度, 相对初始)。 */
    public long getNextOffset() {
        return nextOffset;
    }

    public boolean isClosed() {
        return closed;
    }

    public void close() {
        this.closed = true;
    }

    public int bufferedFragmentCount() {
        return fragments.size();
    }

    public int bufferedBytes() {
        return totalBufferedBytes;
    }

    /** 丢弃过旧/超出容量缓存，回收内存。 */
    public void trimToLimit(int maxFragments) {
        while (fragments.size() > maxFragments) {
            Long last = fragments.lastKey();
            byte[] removed = fragments.remove(last);
            totalBufferedBytes -= removed.length;
        }
    }
}
