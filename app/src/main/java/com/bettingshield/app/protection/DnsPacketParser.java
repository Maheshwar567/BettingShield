package com.bettingshield.app.protection;

import java.nio.ByteBuffer;
import java.util.Locale;

/**
 * Lightweight pure-Java IPv4, UDP, and DNS wire protocol parser and builder.
 * Operates on raw byte buffers without external native libraries.
 */
public class DnsPacketParser {

    public static class DnsQueryInfo {
        public final int transactionId;
        public final String qName;
        public final int qType;
        public final int qClass;
        public final int ipHeaderLen;
        public final int udpHeaderLen;
        public final int dnsOffset;
        public final int questionEndOffset;
        public final byte[] srcIp = new byte[4];
        public final byte[] dstIp = new byte[4];
        public final int srcPort;
        public final int dstPort;

        public DnsQueryInfo(int transactionId, String qName, int qType, int qClass,
                            int ipHeaderLen, int udpHeaderLen, int dnsOffset, int questionEndOffset,
                            byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
            this.transactionId = transactionId;
            this.qName = qName;
            this.qType = qType;
            this.qClass = qClass;
            this.ipHeaderLen = ipHeaderLen;
            this.udpHeaderLen = udpHeaderLen;
            this.dnsOffset = dnsOffset;
            this.questionEndOffset = questionEndOffset;
            System.arraycopy(srcIp, 0, this.srcIp, 0, 4);
            System.arraycopy(dstIp, 0, this.dstIp, 0, 4);
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }
    }

    /**
     * Parses an IPv4 UDP packet containing a DNS query.
     * Returns null if the packet is not a valid IPv4 UDP DNS query.
     */
    public static DnsQueryInfo parseDnsQuery(byte[] packet, int length) {
        if (length < 20 + 8 + 12) {
            return null; // Minimum IPv4 (20) + UDP (8) + DNS header (12)
        }

        // 1. Verify IPv4
        int versionAndIhl = packet[0] & 0xFF;
        int version = versionAndIhl >> 4;
        if (version != 4) {
            return null; // IPv4 only for this parsing path
        }

        int ipHeaderLen = (versionAndIhl & 0x0F) * 4;
        if (length < ipHeaderLen + 8 + 12) {
            return null;
        }

        // 2. Verify Protocol is UDP (17)
        int protocol = packet[9] & 0xFF;
        if (protocol != 17) {
            return null;
        }

        byte[] srcIp = new byte[4];
        byte[] dstIp = new byte[4];
        System.arraycopy(packet, 12, srcIp, 0, 4);
        System.arraycopy(packet, 16, dstIp, 0, 4);

        // 3. UDP Header
        int udpOffset = ipHeaderLen;
        int srcPort = ((packet[udpOffset] & 0xFF) << 8) | (packet[udpOffset + 1] & 0xFF);
        int dstPort = ((packet[udpOffset + 2] & 0xFF) << 8) | (packet[udpOffset + 3] & 0xFF);
        int udpLen = ((packet[udpOffset + 4] & 0xFF) << 8) | (packet[udpOffset + 5] & 0xFF);

        if (dstPort != 53 || length < ipHeaderLen + udpLen) {
            return null; // Not destined for DNS port 53 or truncated
        }

        // 4. DNS Header
        int dnsOffset = ipHeaderLen + 8;
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

        // 5. Parse Question Name (QNAME)
        int pos = dnsOffset + 12;
        StringBuilder qNameBuilder = new StringBuilder();

        while (pos < length) {
            int labelLen = packet[pos] & 0xFF;
            if (labelLen == 0) {
                pos++; // End of QNAME
                break;
            }
            if ((labelLen & 0xC0) != 0) {
                // Compression pointer in query question is invalid in standard DNS
                return null;
            }
            pos++;
            if (pos + labelLen > length) {
                return null;
            }

            if (qNameBuilder.length() > 0) {
                qNameBuilder.append('.');
            }
            qNameBuilder.append(new String(packet, pos, labelLen).toLowerCase(Locale.US));
            pos += labelLen;
        }

        if (pos + 4 > length) {
            return null; // Missing QTYPE or QCLASS
        }

        int qType = ((packet[pos] & 0xFF) << 8) | (packet[pos + 1] & 0xFF);
        int qClass = ((packet[pos + 2] & 0xFF) << 8) | (packet[pos + 3] & 0xFF);
        int questionEndOffset = pos + 4;

        return new DnsQueryInfo(
                transactionId,
                qNameBuilder.toString(),
                qType,
                qClass,
                ipHeaderLen,
                8,
                dnsOffset,
                questionEndOffset,
                srcIp,
                dstIp,
                srcPort,
                dstPort
        );
    }

    /**
     * Constructs a synthetic DNS response packet blocking the query (pointing to 0.0.0.0 or NXDOMAIN).
     */
    public static byte[] buildBlockedDnsResponse(byte[] originalPacket, DnsQueryInfo info) {
        int dnsQuestionLen = info.questionEndOffset - info.dnsOffset;
        
        // Response format:
        // IPv4 Header (20 bytes)
        // UDP Header (8 bytes)
        // DNS Header (12 bytes)
        // Question Section (dnsQuestionLen - 12 bytes)
        // Answer Section (16 bytes for A record answer pointing to 0.0.0.0)
        boolean isTypeA = (info.qType == 1); // 1 = A record

        int answerLen = isTypeA ? 16 : 0;
        int totalDnsLen = dnsQuestionLen + answerLen;
        int totalUdpLen = 8 + totalDnsLen;
        int totalIpLen = 20 + totalUdpLen;

        byte[] response = new byte[totalIpLen];
        ByteBuffer buf = ByteBuffer.wrap(response);

        // --- IPv4 Header ---
        buf.put((byte) 0x45); // Version 4, IHL 5 (20 bytes)
        buf.put((byte) 0x00); // DSCP/ECN
        buf.putShort((short) totalIpLen);
        buf.putShort((short) 0x1234); // Identification
        buf.putShort((short) 0x4000); // Flags: Don't Fragment
        buf.put((byte) 64);   // TTL
        buf.put((byte) 17);   // Protocol: UDP
        buf.putShort((short) 0); // Header Checksum placeholder

        // Swap IP addresses (Response goes from original Dst to original Src)
        buf.put(info.dstIp);
        buf.put(info.srcIp);

        // Compute and write IPv4 header checksum
        int ipChecksum = computeIpChecksum(response, 0, 20);
        buf.putShort(10, (short) ipChecksum);

        // --- UDP Header ---
        buf.putShort((short) info.dstPort); // Src Port (53)
        buf.putShort((short) info.srcPort); // Dst Port (Client Port)
        buf.putShort((short) totalUdpLen);
        buf.putShort((short) 0x0000); // UDP checksum (optional in IPv4, 0 is valid)

        // --- DNS Header ---
        buf.putShort((short) info.transactionId);
        // Flags: QR=1 (Response), AA=1, RA=1, RCODE = isTypeA ? NOERROR(0) : NXDOMAIN(3)
        short flags = isTypeA ? (short) 0x8180 : (short) 0x8183;
        buf.putShort(flags);
        buf.putShort((short) 1); // QDCOUNT: 1
        buf.putShort(isTypeA ? (short) 1 : (short) 0); // ANCOUNT: 1 if A, 0 if NXDOMAIN
        buf.putShort((short) 0); // NSCOUNT: 0
        buf.putShort((short) 0); // ARCOUNT: 0

        // Copy Question Section directly from original packet
        int questionStart = info.dnsOffset + 12;
        int questionLength = info.questionEndOffset - questionStart;
        buf.put(originalPacket, questionStart, questionLength);

        // If Type A, append synthetic A answer: 0.0.0.0
        if (isTypeA) {
            buf.putShort((short) 0xC00C); // Pointer to QNAME at offset 12 in DNS message
            buf.putShort((short) 1);      // Type A
            buf.putShort((short) 1);      // Class IN
            buf.putInt(60);               // TTL: 60 seconds
            buf.putShort((short) 4);      // Data Length: 4 bytes
            buf.put((byte) 0);            // 0.0.0.0
            buf.put((byte) 0);
            buf.put((byte) 0);
            buf.put((byte) 0);
        }

        return response;
    }

    /**
     * Builds an IPv4 UDP packet containing the upstream DNS response to forward back to the client.
     */
    public static byte[] buildForwardedDnsResponse(byte[] upstreamDnsPayload, int dnsPayloadLen, DnsQueryInfo info) {
        int totalUdpLen = 8 + dnsPayloadLen;
        int totalIpLen = 20 + totalUdpLen;

        byte[] response = new byte[totalIpLen];
        ByteBuffer buf = ByteBuffer.wrap(response);

        // IPv4 Header
        buf.put((byte) 0x45);
        buf.put((byte) 0x00);
        buf.putShort((short) totalIpLen);
        buf.putShort((short) 0x1234);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 17); // UDP
        buf.putShort((short) 0); // Checksum placeholder

        // Swap IPs
        buf.put(info.dstIp);
        buf.put(info.srcIp);

        // Compute IP checksum
        int ipChecksum = computeIpChecksum(response, 0, 20);
        buf.putShort(10, (short) ipChecksum);

        // UDP Header
        buf.putShort((short) info.dstPort);
        buf.putShort((short) info.srcPort);
        buf.putShort((short) totalUdpLen);
        buf.putShort((short) 0x0000);

        // Upstream DNS Payload
        buf.put(upstreamDnsPayload, 0, dnsPayloadLen);

        return response;
    }

    /**
     * Computes the 16-bit one's complement sum for IPv4 header.
     */
    public static int computeIpChecksum(byte[] buf, int offset, int length) {
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
}
