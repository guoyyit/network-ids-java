package com.github.guoyyit.networkidsjava.model;

/**
 * TCP 标志位工具。标志位按 RFC 793 的 8bit 掩码表示。
 */
public final class TcpFlags {
    public static final int FIN = 0x01;
    public static final int SYN = 0x02;
    public static final int RST = 0x04;
    public static final int PSH = 0x08;
    public static final int ACK = 0x10;
    public static final int URG = 0x20;

    private TcpFlags() {
    }

    public static boolean isSet(int flags, int bit) {
        return (flags & bit) == bit;
    }

    /** SYN+FIN、SYN+RST 等互斥组合为非法。 */
    public static boolean isValidCombination(int flags) {
        // 仅保留低 6 个定义位，出现保留位视为畸形。
        if ((flags & 0xC0) != 0) {
            return false;
        }
        boolean syn = isSet(flags, SYN);
        boolean fin = isSet(flags, FIN);
        boolean rst = isSet(flags, RST);
        // SYN 不得与 FIN 或 RST 同时出现。
        return !(syn && (fin || rst));
    }

    public static String describe(int flags) {
        StringBuilder sb = new StringBuilder();
        if (isSet(flags, URG)) {
            sb.append("U");
        }
        if (isSet(flags, ACK)) {
            sb.append("A");
        }
        if (isSet(flags, PSH)) {
            sb.append("P");
        }
        if (isSet(flags, RST)) {
            sb.append("R");
        }
        if (isSet(flags, SYN)) {
            sb.append("S");
        }
        if (isSet(flags, FIN)) {
            sb.append("F");
        }
        return sb.length() == 0 ? "." : sb.toString();
    }
}
