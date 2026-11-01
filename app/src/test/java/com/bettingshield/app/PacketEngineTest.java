package com.bettingshield.app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.bettingshield.app.protection.BettingVpnService;
import com.bettingshield.app.protection.ip.CheckSum;
import com.bettingshield.app.protection.ip.IPPacket;
import com.bettingshield.app.protection.ip.UDPPacket;

import org.junit.Test;

import java.net.InetAddress;
import java.nio.ByteBuffer;

public class PacketEngineTest {

    @Test
    public void testIpv4DnsPacketAndChecksum() throws Exception {
        // Construct standard DNS query for playveer.com
        byte[] dnsHeaderAndQuestion = new byte[]{
                (byte) 0x34, (byte) 0x12, // Transaction ID
                (byte) 0x01, (byte) 0x00, // Standard query
                (byte) 0x00, (byte) 0x01, // QDCOUNT: 1
                (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00,
                // QNAME: playveer.com
                0x08, 'p', 'l', 'a', 'y', 'v', 'e', 'e', 'r',
                0x03, 'c', 'o', 'm',
                0x00,
                0x00, 0x01, // Type A
                0x00, 0x01  // Class IN
        };

        int udpLen = 8 + dnsHeaderAndQuestion.length;
        int ipLen = 20 + udpLen;
        byte[] requestPacket = new byte[ipLen];
        ByteBuffer buf = ByteBuffer.wrap(requestPacket);

        buf.put((byte) 0x45);
        buf.put((byte) 0x00);
        buf.putShort((short) ipLen);
        buf.putShort((short) 100);
        buf.putShort((short) 0);
        buf.put((byte) 64);
        buf.put((byte) 17); // UDP
        buf.putShort((short) 0);
        buf.put(new byte[]{10, 0, 2, 15});   // TUN source
        buf.put(new byte[]{10, 10, 10, 10}); // Virtual DNS

        buf.putShort((short) 45678); // Client port
        buf.putShort((short) 53);    // DNS port
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);
        buf.put(dnsHeaderAndQuestion);

        // 1. Test parsing via UDPPacket
        UDPPacket udpReq = new UDPPacket(requestPacket, 0, ipLen);
        assertEquals(4, udpReq.getVersion());
        assertEquals(17, udpReq.getProt());
        assertEquals(45678, udpReq.getSourcePort());
        assertEquals(53, udpReq.getDestPort());

        // 2. Test QName parsing
        int hdrLen = udpReq.getHeaderLength();
        int ipOffs = udpReq.getIPPacketOffset();
        int offs = ipOffs + hdrLen;
        int len = udpReq.getIPPacketLength() - hdrLen;

        String qName = BettingVpnService.parseQName(requestPacket, offs, len);
        assertEquals("playveer.com", qName);

        // 3. Test synthetic blocked response generation
        byte[] syntheticDns = BettingVpnService.buildSyntheticBlockedDnsPayload(requestPacket, offs, len);
        assertNotNull(syntheticDns);
        assertTrue(syntheticDns.length > 12);

        // Verify DNS transaction ID matches
        assertEquals((byte) 0x34, syntheticDns[0]);
        assertEquals((byte) 0x12, syntheticDns[1]);

        // 4. Construct response UDPPacket exactly as BettingVpnService does
        int totalRespLen = hdrLen + syntheticDns.length;
        byte[] responsePacket = new byte[totalRespLen];
        System.arraycopy(syntheticDns, 0, responsePacket, hdrLen, syntheticDns.length);

        UDPPacket udpResp = UDPPacket.createUDPPacket(responsePacket, ipOffs, totalRespLen, 4);
        udpResp.updateHeader(64, 17, udpReq.getDestIP(), udpReq.getSourceIP());
        udpResp.updateHeader(udpReq.getDestPort(), udpReq.getSourcePort());

        // Verify IP fields
        assertEquals(4, udpResp.getVersion());
        assertEquals(totalRespLen, udpResp.getIPPacketLength());
        assertEquals(InetAddress.getByName("10.10.10.10"), IPPacket.int2ip(udpResp.getSourceIP()));
        assertEquals(InetAddress.getByName("10.0.2.15"), IPPacket.int2ip(udpResp.getDestIP()));

        // Verify UDP fields
        assertEquals(53, udpResp.getSourcePort());
        assertEquals(45678, udpResp.getDestPort());

        // Verify IP checksum is 0 (valid)
        int ipCheckSumResult = CheckSum.chkSum(responsePacket, 0, 20);
        assertEquals(0, ipCheckSumResult);

        // Verify UDP checksum is valid
        int udpCheckSumResult = udpResp.checkCheckSum();
        assertEquals(0, udpCheckSumResult);
    }

    @Test
    public void testIpv6DnsPacketAndChecksum() throws Exception {
        byte[] dnsPayload = new byte[]{
                (byte) 0xFE, (byte) 0xDC,
                (byte) 0x01, (byte) 0x00,
                (byte) 0x00, (byte) 0x01,
                (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00,
                0x06, 'b', 'e', 't', '3', '6', '5',
                0x03, 'c', 'o', 'm',
                0x00,
                0x00, 0x1C, // AAAA
                0x00, 0x01
        };

        int udpLen = 8 + dnsPayload.length;
        int ipLen = 40 + udpLen;
        byte[] requestPacket = new byte[ipLen];
        ByteBuffer buf = ByteBuffer.wrap(requestPacket);

        buf.put((byte) 0x60);
        buf.put((byte) 0x00);
        buf.putShort((short) 0);
        buf.putShort((short) udpLen);
        buf.put((byte) 17); // UDP
        buf.put((byte) 64);
        byte[] srcIpv6 = InetAddress.getByName("fdc8:1095:91e1:aaaa:aaaa:aaaa:aaaa:aaa2").getAddress();
        byte[] dstIpv6 = InetAddress.getByName("fdc8:1095:91e1:aaaa:aaaa:aaaa:aaaa:aaa1").getAddress();
        buf.put(srcIpv6);
        buf.put(dstIpv6);

        buf.putShort((short) 51234);
        buf.putShort((short) 53);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);
        buf.put(dnsPayload);

        UDPPacket udpReq = new UDPPacket(requestPacket, 0, ipLen);
        assertEquals(6, udpReq.getVersion());
        assertEquals(17, udpReq.getProt());
        assertEquals(51234, udpReq.getSourcePort());
        assertEquals(53, udpReq.getDestPort());

        int hdrLen = udpReq.getHeaderLength();
        int offs = hdrLen;
        int len = ipLen - hdrLen;

        String qName = BettingVpnService.parseQName(requestPacket, offs, len);
        assertEquals("bet365.com", qName);

        byte[] syntheticDns = BettingVpnService.buildSyntheticBlockedDnsPayload(requestPacket, offs, len);
        assertNotNull(syntheticDns);

        int totalRespLen = hdrLen + syntheticDns.length;
        byte[] responsePacket = new byte[totalRespLen];
        System.arraycopy(syntheticDns, 0, responsePacket, hdrLen, syntheticDns.length);

        UDPPacket udpResp = UDPPacket.createUDPPacket(responsePacket, 0, totalRespLen, 6);
        udpResp.updateHeader(64, 17, udpReq.getDestIP(), udpReq.getSourceIP());
        udpResp.updateHeader(udpReq.getDestPort(), udpReq.getSourcePort());

        assertEquals(6, udpResp.getVersion());
        assertEquals(53, udpResp.getSourcePort());
        assertEquals(51234, udpResp.getDestPort());

        // Verify IPv6 UDP checksum is valid
        int udpCheckSumResult = udpResp.checkCheckSum();
        assertEquals(0, udpCheckSumResult);
    }
}
