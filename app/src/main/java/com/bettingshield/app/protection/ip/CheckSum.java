package com.bettingshield.app.protection.ip;

/**
 * Standard 16-bit Internet checksum calculation for IP and UDP headers.
 */
public class CheckSum {

    public static int chkSum(byte[] buf, int off, int cnt) {
        int sum = 0;

        for (int i = 0; i < cnt; i = i + 2) {
            int val = ((buf[off + i] & 0xFF) << 8);
            if (i + 1 < cnt) {
                val = val + (buf[off + i + 1] & 0xFF);
            }
            sum = sum + val;
        }

        while ((sum >> 16) != 0) {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        sum = (~sum) & 0xffff;
        return sum;
    }
}
