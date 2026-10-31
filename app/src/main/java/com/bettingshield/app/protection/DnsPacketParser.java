package com.bettingshield.app.protection;

import java.nio.ByteBuffer;
import java.util.Locale;

/**
 * Lightweight pure-Java IPv4, IPv6, UDP, and DNS wire protocol parser and builder.
 * Operates on raw byte buffers without external native libraries.
 */
public class DnsPacketParser {

    public static class DnsQueryInfo {
        public final int ipVersion; // 4 or 6
        public final int transactionId;
        public final String qName;
        public final int qType;
        public final int qClass;
        public final int ipHeaderLen;
        public final int udpOffset;
        public final int dnsOffset;
        public final int dnsPayloadLength;
        public final int questionEndOffset;
        public final byte[] srcIp; // 4 bytes (IPv4) or 16 bytes (IPv6)
        public final byte[] dstIp;
        public final int srcPort;
        public final int dstPort;

        public DnsQueryInfo(int ipVersion, int transactionId, String qName, int qType, int qClass,
                            int ipHeaderLen, int udpOffset, int dnsOffset, int dnsPayloadLength,
                            int questionEndOffset, byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
            this.ipVersion = ipVersion;
            this.transactionId = transactionId;
            this.qName = qName;
            this.qType = qType;
            this.qClass = qClass;
            this.ipHeaderLen = ipHeaderLen;
            this.udpOffset = udpOffset;
            this.dnsOffset = dnsOffset;
            this.dnsPayloadLength = dnsPayloadLength;
            this.questionEndOffset = questionEndOffset;
            this.srcIp = srcIp.clone();
            this.dstIp = dstIp.clone();
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }
    }

    /**
     * Parses an IPv4 or IPv6 UDP packet containing a DNS query.
     * Returns null if the packet is not a valid DNS query.
     */
    public static DnsQueryInfo parseDnsQuery(byte[] packet, int length) {
        if (packet == null || length < 28) {
            return null;
        }

        int version = (packet[0] & 0xFF) >> 4;
        int ipHeaderLen;
        int udpOffset;
        int srcPort;
        int dstPort;
        int udpLen;
        int dnsOffset;
        int dnsPayloadLength;
        byte[] srcIp;
        byte[] dstIp;

        if (version == 4) {
            ipHeaderLen = (packet[0] & 0x0F) * 4;
            if (ipHeaderLen < 20 || length < ipHeaderLen + 8 + 12) {
                return null;
            }
            int protocol = packet[9] & 0xFF;
            if (protocol != 17) { // 17 = UDP
                return null;
            }
            udpOffset = ipHeaderLen;
            srcPort = ((packet[udpOffset] & 0xFF) << 8) | (packet[udpOffset + 1] & 0xFF);
            dstPort = ((packet[udpOffset + 2] & 0xFF) << 8) | (packet[udpOffset + 3] & 0xFF);
            udpLen = ((packet[udpOffset + 4] & 0xFF) << 8) | (packet[udpOffset + 5] & 0xFF);

            if (dstPort != 53 || udpLen < 20 || length < ipHeaderLen + udpLen) {
                return null;
            }

            dnsOffset = udpOffset + 8;
            dnsPayloadLength = udpLen - 8;

            srcIp = new byte[4];
            dstIp = new byte[4];
            System.arraycopy(packet, 12, srcIp, 0, 4);
            System.arraycopy(packet, 16, dstIp, 0, 4);

        } else if (version == 6) {
            ipHeaderLen = 40;
            if (length < 40 + 8 + 12) {
                return null;
            }
            int nextHeader = packet[6] & 0xFF;
            if (nextHeader != 17) { // 17 = UDP
                return null;
            }
            udpOffset = 40;
            srcPort = ((packet[udpOffset] & 0xFF) << 8) | (packet[udpOffset + 1] & 0xFF);
            dstPort = ((packet[udpOffset + 2] & 0xFF) << 8) | (packet[udpOffset + 3] & 0xFF);
            udpLen = ((packet[udpOffset + 4] & 0xFF) << 8) | (packet[udpOffset + 5] & 0xFF);

            if (dstPort != 53 || udpLen < 20 || length < ipHeaderLen + udpLen) {
                return null;
            }

            dnsOffset = udpOffset + 8;
            dnsPayloadLength = udpLen - 8;

            srcIp = new byte[16];
            dstIp = new byte[16];
            System.arraycopy(packet, 8, srcIp, 0, 16);
            System.arraycopy(packet, 24, dstIp, 0, 16);

        } else {
            return null;
        }

        if (dnsPayloadLength < 12) {
            return null;
        }

        // Parse DNS Header
        int transactionId = ((packet[dnsOffset] & 0xFF) << 8) | (packet[dnsOffset + 1] & 0xFF);
        int flags = ((packet[dnsOffset + 2] & 0xFF) << 8) | (packet[dnsOffset + 3] & 0xFF);
        boolean isQuery = (flags & 0x8000) == 0;
        if (!isQuery) {
            return null; // Ignore responses
        }

        int qdCount = ((packet[dnsOffset + 4] & 0xFF) << 8) | (packet[dnsOffset + 5] & 0xFF);
        if (qdCount < 1) {
            return null;
        }

        // Parse Question Name (QNAME)
        int pos = dnsOffset + 12;
        int dnsEnd = dnsOffset + dnsPayloadLength;
        StringBuilder qNameBuilder = new StringBuilder();

        while (pos < dnsEnd) {
            int labelLen = packet[pos] & 0xFF;
            if (labelLen == 0) {
                pos++; // End of QNAME
                break;
            }
            if ((labelLen & 0xC0) != 0) {
                return null; // Pointer compression in query question is invalid
            }
            pos++;
            if (pos + labelLen > dnsEnd) {
                return null;
            }
            if (qNameBuilder.length() > 0) {
                qNameBuilder.append('.');
            }
            qNameBuilder.append(new String(packet, pos, labelLen).toLowerCase(Locale.US));
            pos += labelLen;
        }

        if (pos + 4 > dnsEnd) {
            return null; // Missing QTYPE or QCLASS
        }

        int qType = ((packet[pos] & 0xFF) << 8) | (packet[pos + 1] & 0xFF);
        int qClass = ((packet[pos + 2] & 0xFF) << 8) | (packet[pos + 3] & 0xFF);
        int questionEndOffset = pos + 4;

        return new DnsQueryInfo(
                version,
                transactionId,
                qNameBuilder.toString(),
                qType,
                qClass,
                ipHeaderLen,
                udpOffset,
                dnsOffset,
                dnsPayloadLength,
                questionEndOffset,
                srcIp,
                dstIp,
                srcPort,
                dstPort
        );
    }

    /**
     * Constructs a synthetic DNS response packet blocking the query (pointing to 0.0.0.0, ::, or NXDOMAIN).
     */
    public static byte[] buildBlockedDnsResponse(byte[] originalPacket, DnsQueryInfo info) {
        int questionSectionLen = info.questionEndOffset - (info.dnsOffset + 12);

        boolean isTypeA = (info.qType == 1);       // IPv4 A record
        boolean isTypeAAAA = (info.qType == 28);   // IPv6 AAAA record

        int answerLen = 0;
        if (isTypeA) {
            answerLen = 16; // 2(ptr) + 2(type) + 2(class) + 4(ttl) + 2(len) + 4(ip)
        } else if (isTypeAAAA) {
            answerLen = 28; // 2(ptr) + 2(type) + 2(class) + 4(ttl) + 2(len) + 16(ip)
        }

        int dnsLen = 12 + questionSectionLen + answerLen;
        byte[] dnsPayload = new byte[dnsLen];
        ByteBuffer dnsBuf = ByteBuffer.wrap(dnsPayload);

        // Transaction ID
        dnsBuf.putShort((short) info.transactionId);

        // Flags: If A or AAAA -> 0x8180 (NOERROR response), otherwise 0x8183 (NXDOMAIN)
        if (isTypeA || isTypeAAAA) {
            dnsBuf.putShort((short) 0x8180); // Response, Recursion Desired + Available, NOERROR
            dnsBuf.putShort((short) 1);      // QDCOUNT
            dnsBuf.putShort((short) 1);      // ANCOUNT
        } else {
            dnsBuf.putShort((short) 0x8183); // Response, NXDOMAIN
            dnsBuf.putShort((short) 1);      // QDCOUNT
            dnsBuf.putShort((short) 0);      // ANCOUNT
        }
        dnsBuf.putShort((short) 0);          // NSCOUNT
        dnsBuf.putShort((short) 0);          // ARCOUNT

        // Copy Question section from original packet
        dnsBuf.put(originalPacket, info.dnsOffset + 12, questionSectionLen);

        if (isTypeA) {
            dnsBuf.putShort((short) 0xC00C); // Pointer to question name at offset 12
            dnsBuf.putShort((short) 1);      // Type A
            dnsBuf.putShort((short) 1);      // Class IN
            dnsBuf.putInt(60);               // TTL: 60s
            dnsBuf.putShort((short) 4);      // Length: 4
            dnsBuf.putInt(0);                // 0.0.0.0
        } else if (isTypeAAAA) {
            dnsBuf.putShort((short) 0xC00C); // Pointer to question name at offset 12
            dnsBuf.putShort((short) 28);     // Type AAAA
            dnsBuf.putShort((short) 1);      // Class IN
            dnsBuf.putInt(60);               // TTL: 60s
            dnsBuf.putShort((short) 16);     // Length: 16
            for (int i = 0; i < 16; i++) {
                dnsBuf.put((byte) 0);        // :: (all zeroes)
            }
        }

        // Wrap into IP/UDP packet targeting client
        if (info.ipVersion == 4) {
            return wrapInIpv4Udp(dnsPayload, 0, dnsLen, info.dstIp, info.srcIp, info.dstPort, info.srcPort);
        } else {
            return wrapInIpv6Udp(dnsPayload, 0, dnsLen, info.dstIp, info.srcIp, info.dstPort, info.srcPort);
        }
    }

    /**
     * Builds an IP/UDP packet containing the upstream DNS response to forward back to the client.
     */
    public static byte[] buildForwardedDnsResponse(byte[] upstreamDnsPayload, int dnsPayloadLen, DnsQueryInfo info) {
        if (info.ipVersion == 4) {
            return wrapInIpv4Udp(upstreamDnsPayload, 0, dnsPayloadLen, info.dstIp, info.srcIp, info.dstPort, info.srcPort);
        } else {
            return wrapInIpv6Udp(upstreamDnsPayload, 0, dnsPayloadLen, info.dstIp, info.srcIp, info.dstPort, info.srcPort);
        }
    }

    private static byte[] wrapInIpv4Udp(byte[] payload, int offset, int length,
                                        byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
        int udpLen = 8 + length;
        int ipLen = 20 + udpLen;
        byte[] packet = new byte[ipLen];
        ByteBuffer buf = ByteBuffer.wrap(packet);

        // IPv4 Header (20 bytes)
        buf.put((byte) 0x45); // Version 4, IHL 5
        buf.put((byte) 0x00);
        buf.putShort((short) ipLen);
        buf.putShort((short) 0x1234);
        buf.putShort((short) 0x4000); // DF
        buf.put((byte) 64);           // TTL
        buf.put((byte) 17);           // Protocol UDP
        buf.putShort((short) 0);      // IP Checksum placeholder
        buf.put(srcIp);
        buf.put(dstIp);

        int ipChecksum = computeChecksum(packet, 0, 20);
        buf.putShort(10, (short) ipChecksum);

        // UDP Header (8 bytes)
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0); // UDP Checksum placeholder
        buf.put(payload, offset, length);

        int udpChecksum = computeUdpChecksumIpv4(srcIp, dstIp, packet, 20, udpLen);
        buf.putShort(26, (short) udpChecksum);

        return packet;
    }

    private static byte[] wrapInIpv6Udp(byte[] payload, int offset, int length,
                                        byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
        int udpLen = 8 + length;
        int ipLen = 40 + udpLen;
        byte[] packet = new byte[ipLen];
        ByteBuffer buf = ByteBuffer.wrap(packet);

        // IPv6 Header (40 bytes)
        buf.put((byte) 0x60);
        buf.put((byte) 0x00);
        buf.putShort((short) 0x0000); // Flow label
        buf.putShort((short) udpLen); // Payload length
        buf.put((byte) 17);           // Next Header (UDP)
        buf.put((byte) 64);           // Hop Limit
        buf.put(srcIp);               // 16 bytes
        buf.put(dstIp);               // 16 bytes

        // UDP Header (8 bytes)
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0); // UDP Checksum placeholder
        buf.put(payload, offset, length);

        int udpChecksum = computeUdpChecksumIpv6(srcIp, dstIp, packet, 40, udpLen);
        buf.putShort(46, (short) udpChecksum);

        return packet;
    }

    public static int computeChecksum(byte[] buf, int offset, int length) {
        int sum = 0;
        int i = offset;
        while (length > 1) {
            sum += (((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF));
            i += 2;
            length -= 2;
        }
        if (length > 0) {
            sum += ((buf[i] & 0xFF) << 8);
        }
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~sum & 0xFFFF;
    }

    private static int computeUdpChecksumIpv4(byte[] srcIp, byte[] dstIp, byte[] packet, int udpOffset, int udpLen) {
        int sum = 0;
        // Pseudo header: Src IP (4 bytes), Dst IP (4 bytes), Protocol (17), UDP Length
        for (int i = 0; i < 4; i += 2) {
            sum += (((srcIp[i] & 0xFF) << 8) | (srcIp[i + 1] & 0xFF));
            sum += (((dstIp[i] & 0xFF) << 8) | (dstIp[i + 1] & 0xFF));
        }
        sum += 17; // Protocol UDP
        sum += udpLen;

        // UDP Header + Data
        int i = udpOffset;
        int remaining = udpLen;
        while (remaining > 1) {
            sum += (((packet[i] & 0xFF) << 8) | (packet[i + 1] & 0xFF));
            i += 2;
            remaining -= 2;
        }
        if (remaining > 0) {
            sum += ((packet[i] & 0xFF) << 8);
        }
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        int csum = ~sum & 0xFFFF;
        return csum == 0 ? 0xFFFF : csum;
    }

    private static int computeUdpChecksumIpv6(byte[] srcIp, byte[] dstIp, byte[] packet, int udpOffset, int udpLen) {
        int sum = 0;
        // Pseudo header: Src IP (16 bytes), Dst IP (16 bytes), UDP Length (32-bit), Next Header (17)
        for (int i = 0; i < 16; i += 2) {
            sum += (((srcIp[i] & 0xFF) << 8) | (srcIp[i + 1] & 0xFF));
            sum += (((dstIp[i] & 0xFF) << 8) | (dstIp[i + 1] & 0xFF));
        }
        sum += (udpLen >> 16) & 0xFFFF;
        sum += udpLen & 0xFFFF;
        sum += 17; // Next Header UDP

        // UDP Header + Data
        int i = udpOffset;
        int remaining = udpLen;
        while (remaining > 1) {
            sum += (((packet[i] & 0xFF) << 8) | (packet[i + 1] & 0xFF));
            i += 2;
            remaining -= 2;
        }
        if (remaining > 0) {
            sum += ((packet[i] & 0xFF) << 8);
        }
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        int csum = ~sum & 0xFFFF;
        return csum == 0 ? 0xFFFF : csum;
    }
}
