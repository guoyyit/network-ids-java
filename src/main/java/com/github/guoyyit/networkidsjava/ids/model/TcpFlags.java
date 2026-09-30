package com.github.guoyyit.networkidsjava.ids.model;

/**
 * TCP flag bit constants (RFC 793 header flags).
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

    public static boolean has(int mask, int bit) {
        return (mask & bit) != 0;
    }

    public static int parse(String text) {
        int flags = 0;
        for (int i = 0; i < text.length(); i++) {
            switch (Character.toUpperCase(text.charAt(i))) {
                case 'F' -> flags |= FIN;
                case 'S' -> flags |= SYN;
                case 'R' -> flags |= RST;
                case 'P' -> flags |= PSH;
                case 'A' -> flags |= ACK;
                case 'U' -> flags |= URG;
                default -> {
                }
            }
        }
        return flags;
    }

    public static String format(int flags) {
        StringBuilder sb = new StringBuilder();
        if (has(flags, URG)) {
            sb.append('U');
        }
        if (has(flags, ACK)) {
            sb.append('A');
        }
        if (has(flags, PSH)) {
            sb.append('P');
        }
        if (has(flags, RST)) {
            sb.append('R');
        }
        if (has(flags, SYN)) {
            sb.append('S');
        }
        if (has(flags, FIN)) {
            sb.append('F');
        }
        return sb.toString();
    }
}
