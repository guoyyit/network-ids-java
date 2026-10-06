package com.github.guoyyit.networkidsjava.engine;

import java.util.TreeMap;

/**
 * 单方向 TCP 载荷重组器。
 *
 * <p>重叠规则(确定可复现): <b>序列号较小者优先(lowest-SEQ-wins)</b>。
 * 即重组结果始终与报文严格按序到达时一致；同一字节若被两个段覆盖，
 * 取覆盖该字节的、起始序列号最小的段中的内容。乱序、重复、重叠都由此统一处理。
 *
 * <p>起点相同的段(同 SEQ 不同长度，常见于窗口扩大后的重传): <b>先到达者优先</b>，
 * 后到达段只贡献超出既有缓存的尾部字节；被完全覆盖的段整体忽略。
 * 因此对一致数据(短段是长段的前缀)，两种到达顺序的重组结果逐字节相同，
 * 已交付内容不会被覆盖，已缓存的补洞数据也不会被后到的同起点段冲掉。
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

        // 序列号较小者优先；起点相同时先缓存(先到达)的片段优先。
        // 裁掉本段中已被既有片段覆盖的前缀；被完全覆盖则无新字节。
        // 用循环是因为裁过前一片段后，可能紧邻着同起点的下一片段。
        long newEnd = start + length;
        Long head = fragments.floorKey(start);
        while (head != null) {
            long headEnd = head + fragments.get(head).length;
            if (headEnd <= start) {
                break;
            }
            if (headEnd >= newEnd) {
                // 完全被起点更小或相同的既有片段覆盖。
                return new byte[0];
            }
            int cut = (int) (headEnd - start);
            dataOffset += cut;
            start += cut;
            length -= cut;
            head = fragments.floorKey(start);
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

    /**
     * 取出全部剩余缓存片段(按起始序列号升序)并清空缓存。
     * 用于连接被回收前的尽力交付：片段之间可能存在未补齐的空洞，
     * 调用方按返回顺序逐段处理即可，本方法不拼接、不改写偏移。
     */
    public java.util.List<BufferedFragment> drainAll() {
        java.util.List<BufferedFragment> out = new java.util.ArrayList<>();
        for (var e : fragments.entrySet()) {
            out.add(new BufferedFragment(e.getKey(), e.getValue()));
        }
        fragments.clear();
        totalBufferedBytes = 0;
        return out;
    }

    /** 一段仍滞留在缓存中的重组片段。 */
    public static final class BufferedFragment {
        private final long offset;
        private final byte[] data;

        public BufferedFragment(long offset, byte[] data) {
            this.offset = offset;
            this.data = data == null ? new byte[0] : data.clone();
        }

        /** 片段首字节在流内的相对偏移。 */
        public long getOffset() {
            return offset;
        }

        public byte[] getData() {
            return data.clone();
        }
    }
}
