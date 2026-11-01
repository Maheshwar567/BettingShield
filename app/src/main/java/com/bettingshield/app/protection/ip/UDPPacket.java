package com.bettingshield.app.protection.ip;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

/**
 * Pure Java UDP packet wrapper with automatic pseudo-header and UDP checksum calculation.
 */
public class UDPPacket extends IPPacket {

    private final IntBuffer udpHeader;

    public UDPPacket(byte[] packet, int offs, int len) {
        super(packet, offs, len);
        this.udpHeader = ByteBuffer.wrap(packet, offs + ipHdrlen, 8).order(ByteOrder.BIG_ENDIAN).asIntBuffer();
    }

    public static UDPPacket createUDPPacket(byte[] packet, int offs, int len, int version) {
        packet[offs] = ((byte) ((version << 4) & 0xFF));
        UDPPacket udp = new UDPPacket(packet, offs, len);
        udp.initInitialIPHeader();
        return udp;
    }

    public void updateHeader(int sourcePort, int destPort) {
        int[] hdrPacket = new int[2];
        hdrPacket[0] = (sourcePort << 16) + destPort;
        hdrPacket[1] = (len - ipHdrlen) << 16;
        udpHeader.position(0);
        udpHeader.put(hdrPacket);
        hdrPacket[1] = hdrPacket[1] + calculateCheckSum(true);
        udpHeader.put(1, hdrPacket[1]);
    }

    public int checkCheckSum() {
        return calculateCheckSum(false);
    }

    private int calculateCheckSum(boolean internal) {
        int checkSum = 0;
        if (version == 4) {
            int saved = ipHeader.get(2);
            ipHeader.put(2, (17 << 16) + len - ipHdrlen);
            checkSum = CheckSum.chkSum(data, offset + 8, len - 8);
            ipHeader.put(2, saved);
        } else if (version == 6) {
            int[] saved = new int[]{ipHeader.get(0), ipHeader.get(1)};
            ipHeader.put(0, len - ipHdrlen);
            ipHeader.put(1, 17);
            checkSum = CheckSum.chkSum(data, offset, len);
            ipHeader.position(0);
            ipHeader.put(saved);
        } else {
            throw new IllegalStateException("Illegal version:" + version);
        }

        if (internal && checkSum == 0) {
            checkSum = 0xffff;
        }

        return checkSum;
    }

    public int getSourcePort() {
        return udpHeader.get(0) >>> 16;
    }

    public int getDestPort() {
        return udpHeader.get(0) & 0x0000FFFF;
    }

    public int getLength() {
        return udpHeader.get(1) >>> 16;
    }

    public int getIPPacketLength() {
        return super.getLength();
    }

    public int getHeaderLength() {
        return ipHdrlen + 8;
    }

    public int getOffset() {
        return super.getOffset() + ipHdrlen;
    }

    public int getIPPacketOffset() {
        return super.getOffset();
    }
}
