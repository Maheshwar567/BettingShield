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
import android.system.OsConstants;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.bettingshield.app.R;
import com.bettingshield.app.ui.MainActivity;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-performance, non-blocking local DNS-filtering VPN Service.
 * Intercepts DNS queries locally on the device, immediately sinkholing betting/wagering
 * domains to 0.0.0.0 or NXDOMAIN, while asynchronously forwarding legitimate traffic using system,
 * public DNS resolvers, and fallback DNS-over-HTTPS (DoH) to guarantee full, uninterrupted
 * internet connectivity on both Wi-Fi and mobile data (4G/5G, Jio, Airtel, etc.).
 */
public class BettingVpnService extends VpnService {

    private static final String TAG = "BettingVpnService";
    public static final String ACTION_START = "com.bettingshield.app.START_VPN";
    public static final String ACTION_STOP = "com.bettingshield.app.STOP_VPN";
    private static final String CHANNEL_ID = "bettingshield_vpn_channel";
    private static final int NOTIFICATION_ID = 1001;

    private static final int DNS_PORT = 53;

    // Distinct TUN interface addresses and virtual DNS resolver addresses
    private static final String VIRTUAL_IPV4_ADDR = "10.10.10.1";
    private static final String VIRTUAL_IPV4_DNS = "10.10.10.2";
    private static final String VIRTUAL_IPV6_ADDR = "fd00::1";
    private static final String VIRTUAL_IPV6_DNS = "fd00::2";

    private ParcelFileDescriptor vpnInterface;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private ExecutorService readerExecutor;
    private ExecutorService dnsForwarderPool;

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

            // Assign virtual IP to the TUN interface (10.10.10.1/24)
            builder.addAddress(VIRTUAL_IPV4_ADDR, 24);

            // Configure system DNS to point to virtual DNS resolver (10.10.10.2)
            builder.addDnsServer(VIRTUAL_IPV4_DNS);

            // Route ONLY the virtual DNS IP into TUN (10.10.10.2/32)
            // This ensures all non-DNS internet traffic bypasses the VPN completely!
            builder.addRoute(VIRTUAL_IPV4_DNS, 32);

            // Configure IPv6 virtual address and route so IPv6 networks (Jio 5G, Airtel 5G) function normally
            try {
                builder.addAddress(VIRTUAL_IPV6_ADDR, 64);
                builder.addDnsServer(VIRTUAL_IPV6_DNS);
                builder.addRoute(VIRTUAL_IPV6_DNS, 128);
            } catch (Exception e) {
                Log.w(TAG, "IPv6 TUN config not supported by host: " + e.getMessage());
            }

            // CRITICAL: Allow all apps to bypass the VPN for general traffic
            builder.allowBypass();

            // CRITICAL: Explicitly allow both address families so Android does not disable IPv6
            try {
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            } catch (Exception e) {
                Log.w(TAG, "Could not set allowFamily: " + e.getMessage());
            }

            // Set VPN to unmetered on Android 10+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false);
            }

            builder.setBlocking(true);

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface (null)");
                stopSelf();
                return;
            }

            isRunning.set(true);
            ProtectionManager.getInstance(this).onVpnStateChanged(true);

            readerExecutor = Executors.newSingleThreadExecutor();
            dnsForwarderPool = Executors.newFixedThreadPool(16);

            readerExecutor.execute(this::runTunReader);

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
        return host != null && (host.startsWith("10.10.10.") || host.startsWith("fd00::"));
    }

    private void runTunReader() {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
        byte[] packetBuffer = new byte[32767];

        while (isRunning.get()) {
            try {
                int length = in.read(packetBuffer);
                if (length <= 0) continue;

                DnsPacketParser.DnsQueryInfo query = DnsPacketParser.parseDnsQuery(packetBuffer, length);
                if (query == null) {
                    continue; // Skip non-DNS packets
                }

                String domain = query.qName;
                boolean isBlocked = domainFilter.isBlocked(domain);

                if (isBlocked) {
                    // Discreet local sinkhole: synthesize 0.0.0.0 / :: / NXDOMAIN response instantly in 0ms
                    byte[] blockedResponse = DnsPacketParser.buildBlockedDnsResponse(packetBuffer, query);
                    synchronized (out) {
                        out.write(blockedResponse);
                        out.flush();
                    }
                    Log.d(TAG, "Locally filtered wagering domain: " + domain);

                } else {
                    // Legitimate traffic: Dispatch to worker pool
                    final byte[] packetCopy = Arrays.copyOf(packetBuffer, length);
                    final DnsPacketParser.DnsQueryInfo queryCopy = query;

                    dnsForwarderPool.execute(() -> forwardDnsQueryAsync(packetCopy, length, queryCopy, out));
                }

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

    /**
     * Resolves legitimate DNS queries asynchronously without blocking the TUN reader thread.
     * Uses active network resolvers first, then public resolvers, and falls back to DNS-over-HTTPS (DoH)
     * if carrier firewalls or captive portals block raw UDP port 53.
     */
    private void forwardDnsQueryAsync(byte[] packet, int length, DnsPacketParser.DnsQueryInfo query, FileOutputStream out) {
        try {
            byte[] queryPayload = Arrays.copyOfRange(
                    packet,
                    query.dnsOffset,
                    query.dnsOffset + query.dnsPayloadLength
            );

            byte[] responsePayload = null;

            // 1. Fast UDP resolution against active network DNS resolvers (5-20ms)
            for (InetAddress resolver : upstreamResolvers) {
                responsePayload = queryUdp(queryPayload, resolver);
                if (responsePayload != null && responsePayload.length >= 12) {
                    break;
                }
            }

            // 2. If UDP timed out or was blocked by carrier (common on Jio/Airtel mobile data), fallback to DoH (443 HTTPS)
            if (responsePayload == null) {
                responsePayload = queryDoH(queryPayload);
            }

            if (responsePayload != null && responsePayload.length >= 12) {
                byte[] forwardedResponse = DnsPacketParser.buildForwardedDnsResponse(
                        responsePayload, responsePayload.length, query
                );

                synchronized (out) {
                    out.write(forwardedResponse);
                    out.flush();
                }
            }

        } catch (Exception e) {
            Log.w(TAG, "Error resolving " + query.qName + ": " + e.getMessage());
        }
    }

    /**
     * Sends DNS query over protected UDP socket with fast 600ms timeout.
     */
    private byte[] queryUdp(byte[] queryPayload, InetAddress resolver) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            protect(socket);
            socket.setSoTimeout(600);

            DatagramPacket sendPacket = new DatagramPacket(
                    queryPayload, queryPayload.length,
                    resolver, DNS_PORT
            );
            socket.send(sendPacket);

            byte[] recvBuffer = new byte[1500];
            DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length);
            socket.receive(recvPacket);

            return Arrays.copyOf(recvPacket.getData(), recvPacket.getLength());
        } catch (Exception ignored) {
            return null;
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
    }

    /**
     * Resolves DNS queries via RFC 8484 DNS-over-HTTPS (DoH).
     * Runs over port 443 (HTTPS), which is completely immune to carrier UDP port 53 blocking.
     */
    private byte[] queryDoH(byte[] queryPayload) {
        String[] dohEndpoints = {
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/dns-query"
        };

        for (String endpoint : dohEndpoints) {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(endpoint);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/dns-message");
                conn.setRequestProperty("Accept", "application/dns-message");
                conn.setConnectTimeout(1500);
                conn.setReadTimeout(1500);
                conn.setDoOutput(true);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(queryPayload);
                    os.flush();
                }

                if (conn.getResponseCode() == 200) {
                    try (InputStream is = conn.getInputStream();
                         ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                        byte[] buf = new byte[1024];
                        int n;
                        while ((n = is.read(buf)) != -1) {
                            baos.write(buf, 0, n);
                        }
                        byte[] result = baos.toByteArray();
                        if (result.length >= 12) {
                            return result;
                        }
                    }
                }
            } catch (Exception ignored) {
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        return null;
    }

    private synchronized void stopVpn() {
        isRunning.set(false);
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
