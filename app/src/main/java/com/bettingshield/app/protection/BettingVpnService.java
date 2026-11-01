package com.bettingshield.app.protection;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.bettingshield.app.R;
import com.bettingshield.app.protection.ip.UDPPacket;
import com.bettingshield.app.ui.MainActivity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-performance, battle-tested local DNS-filtering VPN Service.
 * Intercepts DNS queries locally on the device, immediately sinkholing betting/wagering
 * domains to 0.0.0.0 or NXDOMAIN, while asynchronously forwarding legitimate traffic using system
 * and public DNS resolvers with exact UDP/IP packet header and checksum reconstruction.
 */
public class BettingVpnService extends VpnService {

    private static final String TAG = "BettingVpnService";
    public static final String ACTION_START = "com.bettingshield.app.START_VPN";
    public static final String ACTION_STOP = "com.bettingshield.app.STOP_VPN";
    private static final String CHANNEL_ID = "bettingshield_vpn_channel";
    private static final int NOTIFICATION_ID = 1001;

    private static final int DNS_PORT = 53;

    // Proven virtual IP parameters (distinct guest subnet and virtual DNS resolver)
    private static final String ADDRESS_IPV4 = "10.0.2.15";
    private static final String VIRTUALDNS_IPV4 = "10.10.10.10";
    private static final String ADDRESS_IPV6 = "fdc8:1095:91e1:aaaa:aaaa:aaaa:aaaa:aaa2";
    private static final String VIRTUALDNS_IPV6 = "fdc8:1095:91e1:aaaa:aaaa:aaaa:aaaa:aaa1";

    private ParcelFileDescriptor vpnInterface;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private ExecutorService readerExecutor;
    private ExecutorService dnsForwarderPool;
    private ConnectivityManager.NetworkCallback networkCallback;

    private DomainFilter domainFilter;
    private final List<InetAddress> upstreamResolvers = Collections.synchronizedList(new ArrayList<>());

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        domainFilter = ProtectionManager.getInstance(this).getDomainFilter();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, buildForegroundNotification());
        startVpn();
        return START_STICKY;
    }

    private synchronized void startVpn() {
        if (isRunning.get()) {
            return;
        }

        try {
            refreshUpstreamResolvers();

            Builder builder = new Builder();
            builder.setSession(getString(R.string.app_name));

            // Assign virtual IP to the TUN interface (10.0.2.15/24)
            builder.addAddress(ADDRESS_IPV4, 24);

            // Configure system DNS to point to virtual DNS resolver (10.10.10.10)
            builder.addDnsServer(VIRTUALDNS_IPV4);

            // Route ONLY the virtual DNS IP into TUN (10.10.10.10/32)
            // This ensures all non-DNS internet traffic flows directly through Wi-Fi or mobile data!
            builder.addRoute(VIRTUALDNS_IPV4, 32);

            // Configure IPv6 virtual address and route
            try {
                builder.addAddress(ADDRESS_IPV6, 48);
                builder.addDnsServer(VIRTUALDNS_IPV6);
                builder.addRoute(VIRTUALDNS_IPV6, 128);
            } catch (Exception e) {
                Log.w(TAG, "IPv6 TUN config not supported by host: " + e.getMessage());
            }

            builder.setBlocking(true);
            builder.setMtu(1500);

            // Set VPN to unmetered on Android 10+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false);
            }

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface (null)");
                stopSelf();
                return;
            }

            isRunning.set(true);
            ProtectionManager.getInstance(this).onVpnStateChanged(true);

            readerExecutor = Executors.newSingleThreadExecutor();
            dnsForwarderPool = Executors.newCachedThreadPool();

            readerExecutor.execute(this::runTunReader);

            // Register dynamic network callback to automatically track Wi-Fi / Mobile data changes
            registerNetworkCallback();

            // Background rule update
            Executors.newSingleThreadExecutor().execute(() -> {
                com.bettingshield.app.updates.RuleUpdateWorker.syncDirect(getApplicationContext());
            });

            Log.i(TAG, "BettingShield VPN filtering engine established successfully");

        } catch (Exception e) {
            Log.e(TAG, "Error starting VPN interface", e);
            stopVpn();
            stopSelf();
        }
    }

    /**
     * Finds active system Wi-Fi / Mobile Data DNS resolvers, with fallback to Google and Cloudflare.
     */
    private void refreshUpstreamResolvers() {
        upstreamResolvers.clear();

        // 1. Discover current active network's DNS servers (Router / Carrier DNS)
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network activeNet = cm.getActiveNetwork();
                if (activeNet != null) {
                    LinkProperties lp = cm.getLinkProperties(activeNet);
                    if (lp != null) {
                        for (InetAddress dns : lp.getDnsServers()) {
                            if (!dns.isLoopbackAddress() && !isLocalVirtualIp(dns)) {
                                upstreamResolvers.add(dns);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not query active network DNS: " + e.getMessage());
        }

        // 2. Add high-reliability public resolvers as fallbacks
        try {
            upstreamResolvers.add(InetAddress.getByName("8.8.8.8"));
            upstreamResolvers.add(InetAddress.getByName("1.1.1.1"));
            upstreamResolvers.add(InetAddress.getByName("8.8.4.4"));
            upstreamResolvers.add(InetAddress.getByName("9.9.9.9"));
            upstreamResolvers.add(InetAddress.getByName("2001:4860:4860::8888"));
            upstreamResolvers.add(InetAddress.getByName("2606:4700:4700::1111"));
        } catch (Exception ignored) {}

        Log.i(TAG, "Loaded " + upstreamResolvers.size() + " active upstream DNS resolvers");
    }

    private boolean isLocalVirtualIp(InetAddress addr) {
        if (addr == null) return false;
        String host = addr.getHostAddress();
        return host != null && (host.startsWith("10.") || host.startsWith("fdc8:"));
    }

    private void runTunReader() {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
        byte[] packetBuffer = new byte[32767];

        while (isRunning.get()) {
            try {
                int length = in.read(packetBuffer);
                if (length <= 0) continue;

                byte[] data = Arrays.copyOf(packetBuffer, length);
                dnsForwarderPool.execute(() -> processPacket(data, length, out));

            } catch (Exception e) {
                if (!isRunning.get()) break;
                Log.w(TAG, "Error in TUN read loop: " + e.getMessage());
            }
        }

        try {
            in.close();
            out.close();
        } catch (IOException ignored) {}
    }

    private void processPacket(byte[] data, int length, FileOutputStream out) {
        try {
            int version = (data[0] & 0xFF) >> 4;
            if (version != 4 && version != 6) {
                return;
            }

            UDPPacket udpRequest = new UDPPacket(data, 0, length);
            if (udpRequest.getProt() != 17) { // 17 = UDP
                return;
            }

            int destPort = udpRequest.getDestPort();
            if (destPort != 53) {
                return;
            }

            int ttl = udpRequest.getTTL();
            int[] sourceIP = udpRequest.getSourceIP();
            int[] destIP = udpRequest.getDestIP();
            int sourcePort = udpRequest.getSourcePort();

            int hdrLen = udpRequest.getHeaderLength();
            int ipOffs = udpRequest.getIPPacketOffset();
            int offs = ipOffs + hdrLen;
            int len = udpRequest.getIPPacketLength() - hdrLen;

            if (len < 12) {
                return;
            }

            String qName = parseQName(data, offs, len);
            boolean isBlocked = qName != null && domainFilter.isBlocked(qName);

            byte[] responseDnsPayload;

            if (isBlocked) {
                responseDnsPayload = buildSyntheticBlockedDnsPayload(data, offs, len);
                Log.d(TAG, "Locally blocked wagering site: " + qName);
            } else {
                responseDnsPayload = forwardUpstream(data, offs, len);
            }

            if (responseDnsPayload == null || responseDnsPayload.length < 12) {
                return;
            }

            int totalIpLen = hdrLen + responseDnsPayload.length;
            byte[] responsePacket = new byte[totalIpLen];
            System.arraycopy(responseDnsPayload, 0, responsePacket, hdrLen, responseDnsPayload.length);

            UDPPacket udpResponse = UDPPacket.createUDPPacket(responsePacket, ipOffs, totalIpLen, version);
            udpResponse.updateHeader(ttl, 17, destIP, sourceIP);
            udpResponse.updateHeader(destPort, sourcePort);

            synchronized (out) {
                out.write(udpResponse.getData(), udpResponse.getIPPacketOffset(), udpResponse.getIPPacketLength());
                out.flush();
            }

        } catch (Exception e) {
            Log.w(TAG, "Error processing DNS packet: " + e.getMessage());
        }
    }

    public static String parseQName(byte[] data, int offs, int len) {
        if (len < 12) return null;
        int flags = ((data[offs + 2] & 0xFF) << 8) | (data[offs + 3] & 0xFF);
        boolean isQuery = (flags & 0x8000) == 0;
        if (!isQuery) return null;

        int qdCount = ((data[offs + 4] & 0xFF) << 8) | (data[offs + 5] & 0xFF);
        if (qdCount < 1) return null;

        int pos = offs + 12;
        int end = offs + len;
        StringBuilder qName = new StringBuilder();

        while (pos < end) {
            int labelLen = data[pos] & 0xFF;
            if (labelLen == 0) {
                break;
            }
            if ((labelLen & 0xC0) != 0) {
                return null;
            }
            pos++;
            if (pos + labelLen > end) return null;
            if (qName.length() > 0) qName.append('.');
            qName.append(new String(data, pos, labelLen).toLowerCase(Locale.US));
            pos += labelLen;
        }

        return qName.toString();
    }

    public static byte[] buildSyntheticBlockedDnsPayload(byte[] data, int offs, int len) {
        if (len < 12) return null;
        int transactionId = ((data[offs] & 0xFF) << 8) | (data[offs + 1] & 0xFF);

        // Find end of Question section
        int pos = offs + 12;
        int end = offs + len;
        while (pos < end) {
            int labelLen = data[pos] & 0xFF;
            if (labelLen == 0) {
                pos++;
                break;
            }
            pos += 1 + labelLen;
        }

        if (pos + 4 > end) return null;
        int qType = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        int questionEnd = pos + 4;
        int questionSectionLen = questionEnd - (offs + 12);

        boolean isTypeA = (qType == 1);
        boolean isTypeAAAA = (qType == 28);

        int answerLen = isTypeA ? 16 : (isTypeAAAA ? 28 : 0);
        int dnsLen = 12 + questionSectionLen + answerLen;

        byte[] dnsPayload = new byte[dnsLen];
        ByteBuffer buf = ByteBuffer.wrap(dnsPayload);

        buf.putShort((short) transactionId);

        if (isTypeA || isTypeAAAA) {
            buf.putShort((short) 0x8180); // Response, Recursion Desired + Available, NOERROR
            buf.putShort((short) 1);      // QDCOUNT: 1
            buf.putShort((short) 1);      // ANCOUNT: 1
        } else {
            buf.putShort((short) 0x8183); // NXDOMAIN
            buf.putShort((short) 1);      // QDCOUNT: 1
            buf.putShort((short) 0);      // ANCOUNT: 0
        }
        buf.putShort((short) 0);          // NSCOUNT: 0
        buf.putShort((short) 0);          // ARCOUNT: 0

        // Question section
        buf.put(data, offs + 12, questionSectionLen);

        if (isTypeA) {
            buf.putShort((short) 0xC00C); // Pointer to question name
            buf.putShort((short) 1);      // Type A
            buf.putShort((short) 1);      // Class IN
            buf.putInt(60);               // TTL: 60s
            buf.putShort((short) 4);      // Length: 4
            buf.putInt(0);                // 0.0.0.0
        } else if (isTypeAAAA) {
            buf.putShort((short) 0xC00C);
            buf.putShort((short) 28);     // Type AAAA
            buf.putShort((short) 1);      // Class IN
            buf.putInt(60);               // TTL: 60s
            buf.putShort((short) 16);     // Length: 16
            for (int i = 0; i < 16; i++) {
                buf.put((byte) 0);        // ::
            }
        }

        return dnsPayload;
    }

    private void registerNetworkCallback() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                networkCallback = new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                        refreshUpstreamResolvers();
                    }

                    @Override
                    public void onAvailable(Network network) {
                        refreshUpstreamResolvers();
                    }
                };
                cm.registerDefaultNetworkCallback(networkCallback);
            }
        } catch (Exception e) {
            Log.w(TAG, "NetworkCallback registration failed: " + e.getMessage());
        }
    }

    private byte[] forwardUpstream(byte[] queryData, int offs, int len) {
        byte[] requestPayload = Arrays.copyOfRange(queryData, offs, offs + len);

        List<InetAddress> targets;
        synchronized (upstreamResolvers) {
            targets = new ArrayList<>(upstreamResolvers);
        }

        if (targets.isEmpty()) {
            try {
                targets.add(InetAddress.getByName("8.8.8.8"));
                targets.add(InetAddress.getByName("1.1.1.1"));
            } catch (Exception ignored) {}
        }

        // Speculative racing across top upstreams (first successful response wins)
        int queryCount = Math.min(targets.size(), 4);
        ExecutorCompletionService<byte[]> completionService = new ExecutorCompletionService<>(dnsForwarderPool);

        for (int i = 0; i < queryCount; i++) {
            final InetAddress resolver = targets.get(i);
            completionService.submit(() -> queryUdp(requestPayload, resolver));
        }

        for (int i = 0; i < queryCount; i++) {
            try {
                Future<byte[]> future = completionService.poll(850, TimeUnit.MILLISECONDS);
                if (future != null) {
                    byte[] resp = future.get();
                    if (resp != null && resp.length >= 12) {
                        return resp;
                    }
                }
            } catch (Exception ignored) {}
        }

        return null;
    }

    private byte[] queryUdp(byte[] payload, InetAddress resolver) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            protect(socket);
            socket.setSoTimeout(750);

            DatagramPacket sendPacket = new DatagramPacket(payload, payload.length, resolver, DNS_PORT);
            socket.send(sendPacket);

            byte[] recvBuf = new byte[1500];
            DatagramPacket recvPacket = new DatagramPacket(recvBuf, recvBuf.length);
            socket.receive(recvPacket);

            if (recvPacket.getLength() >= 12) {
                return Arrays.copyOf(recvPacket.getData(), recvPacket.getLength());
            }
        } catch (Exception ignored) {
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
        return null;
    }

    private synchronized void stopVpn() {
        isRunning.set(false);
        if (networkCallback != null) {
            try {
                ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    cm.unregisterNetworkCallback(networkCallback);
                }
            } catch (Exception ignored) {}
            networkCallback = null;
        }
        if (readerExecutor != null) {
            readerExecutor.shutdownNow();
        }
        if (dnsForwarderPool != null) {
            dnsForwarderPool.shutdownNow();
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException ignored) {}
            vpnInterface = null;
        }
        ProtectionManager.getInstance(this).onVpnStateChanged(false);
        Log.i(TAG, "BettingShield VPN stopped");
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription(getString(R.string.notification_channel_desc));
            channel.setShowBadge(false);

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildForegroundNotification() {
        Intent launchIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, launchIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.notification_title))
                .setContentText(getString(R.string.notification_text))
                .setSmallIcon(R.drawable.ic_shield)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }
}
