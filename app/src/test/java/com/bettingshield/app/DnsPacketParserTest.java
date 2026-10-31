package com.bettingshield.app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.bettingshield.app.protection.DnsPacketParser;

import org.junit.Test;

import java.nio.ByteBuffer;

public class DnsPacketParserTest {

    @Test
    public void testIpv4DnsQueryParsing() {
        // Construct a synthetic IPv4 UDP DNS query packet for "playveer.com"
        byte[] dnsHeaderAndQuestion = new byte[]{
                (byte) 0x12, (byte) 0x34, // Transaction ID
                (byte) 0x01, (byte) 0x00, // Flags (Standard query)
                (byte) 0x00, (byte) 0x01, // QDCOUNT: 1
                (byte) 0x00, (byte) 0x00, // ANCOUNT: 0
                (byte) 0x00, (byte) 0x00, // NSCOUNT: 0
                (byte) 0x00, (byte) 0x00, // ARCOUNT: 0
                // QNAME: playveer.com
                0x08, 'p', 'l', 'a', 'y', 'v', 'e', 'e', 'r',
                0x03, 'c', 'o', 'm',
                0x00,
                // QTYPE: 1 (A)
                0x00, 0x01,
                // QCLASS: 1 (IN)
                0x00, 0x01
        };

        int udpLen = 8 + dnsHeaderAndQuestion.length;
        int ipLen = 20 + udpLen;

        byte[] packet = new byte[ipLen];
        ByteBuffer buf = ByteBuffer.wrap(packet);

        // IPv4 Header
        buf.put((byte) 0x45);
        buf.put((byte) 0x00);
        buf.putShort((short) ipLen);
        buf.putShort((short) 1);
        buf.putShort((short) 0);
        buf.put((byte) 64);
        buf.put((byte) 17); // UDP
        buf.putShort((short) 0);
        buf.put(new byte[]{10, 10, 10, 1}); // Src IP
        buf.put(new byte[]{10, 10, 10, 2}); // Dst IP

        // UDP Header
        buf.putShort((short) 54321); // Src Port
        buf.putShort((short) 53);    // Dst Port
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);

        // DNS Payload
        buf.put(dnsHeaderAndQuestion);

        DnsPacketParser.DnsQueryInfo info = DnsPacketParser.parseDnsQuery(packet, packet.length);
        assertNotNull(info);
        assertEquals(4, info.ipVersion);
        assertEquals(0x1234, info.transactionId);
        assertEquals("playveer.com", info.qName);
        assertEquals(1, info.qType);
        assertEquals(54321, info.srcPort);
        assertEquals(53, info.dstPort);

        // Test building blocked response
        byte[] blockedResp = DnsPacketParser.buildBlockedDnsResponse(packet, info);
        assertNotNull(blockedResp);
        assertTrue(blockedResp.length > 28);
        // Verify response destination IP is 10.10.10.1 (original source)
        assertEquals(10, blockedResp[16]);
        assertEquals(10, blockedResp[17]);
        assertEquals(10, blockedResp[18]);
        assertEquals(1, blockedResp[19]);
    }

    @Test
    public void testIpv6DnsQueryParsing() {
        // Construct a synthetic IPv6 UDP DNS query packet for "bet365.com"
        byte[] dnsHeaderAndQuestion = new byte[]{
                (byte) 0xAB, (byte) 0xCD, // Transaction ID
                (byte) 0x01, (byte) 0x00, // Flags
                (byte) 0x00, (byte) 0x01, // QDCOUNT: 1
                (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00,
                // QNAME: bet365.com
                0x06, 'b', 'e', 't', '3', '6', '5',
                0x03, 'c', 'o', 'm',
                0x00,
                // QTYPE: 28 (AAAA)
                0x00, 0x1C,
                // QCLASS: 1 (IN)
                0x00, 0x01
        };

        int udpLen = 8 + dnsHeaderAndQuestion.length;
        int ipLen = 40 + udpLen;

        byte[] packet = new byte[ipLen];
        ByteBuffer buf = ByteBuffer.wrap(packet);

        // IPv6 Header (40 bytes)
        buf.put((byte) 0x60);
        buf.put((byte) 0x00);
        buf.putShort((short) 0);
        buf.putShort((short) udpLen);
        buf.put((byte) 17); // Next Header: UDP
        buf.put((byte) 64);
        byte[] srcIpv6 = new byte[]{ (byte) 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        byte[] dstIpv6 = new byte[]{ (byte) 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
        buf.put(srcIpv6);
        buf.put(dstIpv6);

        // UDP Header
        buf.putShort((short) 61234);
        buf.putShort((short) 53);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);

        // DNS Payload
        buf.put(dnsHeaderAndQuestion);

        DnsPacketParser.DnsQueryInfo info = DnsPacketParser.parseDnsQuery(packet, packet.length);
        assertNotNull(info);
        assertEquals(6, info.ipVersion);
        assertEquals(0xABCD, info.transactionId);
        assertEquals("bet365.com", info.qName);
        assertEquals(28, info.qType);
        assertEquals(61234, info.srcPort);

        // Test building blocked response
        byte[] blockedResp = DnsPacketParser.buildBlockedDnsResponse(packet, info);
        assertNotNull(blockedResp);
        assertTrue(blockedResp.length > 48);
        // Verify response destination IP matches original source IPv6 (fd00::1)
        assertEquals((byte) 0xFD, blockedResp[24]);
        assertEquals(1, blockedResp[39]);
    }
}
