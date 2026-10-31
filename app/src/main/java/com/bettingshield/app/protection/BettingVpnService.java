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
import com.bettingshield.app.ui.MainActivity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-performance, non-blocking local DNS-filtering VPN Service.
 * Intercepts DNS queries locally on the device, immediately sinkholing betting/wagering
 * domains to 0.0.0.0, while asynchronously forwarding legitimate traffic using system
 * and public DNS resolvers to ensure full internet connectivity on both Wi-Fi and mobile data.
 */
public class BettingVpnService extends VpnService {

    private static final String TAG = "BettingVpnService";
    public static final String ACTION_START = "com.bettingshield.app.START_VPN";
    public static final String ACTION_STOP = "com.bettingshield.app.STOP_VPN";
    private static final String CHANNEL_ID = "bettingshield_vpn_channel";
    private static final int NOTIFICATION_ID = 1001;

    private static final int DNS_PORT = 53;
    private static final String VIRTUAL_DNS_IP = "10.10.10.1";

    private ParcelFileDescriptor vpnInterface;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private ExecutorService readerExecutor;
    private ExecutorService dnsForwarderPool;

    private DomainFilter domainFilter;
    private final List<InetAddress> upstreamResolvers = new ArrayList<>();

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

            // Assign virtual IP to the TUN interface
            builder.addAddress(VIRTUAL_DNS_IP, 32);

            // Configure system DNS to point to the local TUN filter
            builder.addDnsServer(VIRTUAL_DNS_IP);

            // Route ONLY the virtual DNS IP into TUN so all general internet traffic flows normally
            builder.addRoute(VIRTUAL_DNS_IP, 32);

            builder.setBlocking(true);

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface (null)");
                stopSelf();
                return;
            }

            isRunning.set(true);
            ProtectionManager.getInstance(this).onVpnStateChanged(true);

            // 1 thread for TUN reader, 8 worker threads for non-blocking parallel DNS resolution
            readerExecutor = Executors.newSingleThreadExecutor();
            dnsForwarderPool = Executors.newFixedThreadPool(8);

            readerExecutor.execute(this::runTunReader);

            // Trigger background rule update
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
                            if (dns instanceof Inet4Address && !dns.isLoopbackAddress() && !dns.getHostAddress().equals(VIRTUAL_DNS_IP)) {
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
        } catch (Exception ignored) {}

        Log.i(TAG, "Loaded " + upstreamResolvers.size() + " active upstream DNS resolvers");
    }

    private void runTunReader() {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
        byte[] packetBuffer = new byte[32767];

        while (isRunning.get()) {
            try {
                int length = in.read(packetBuffer);
                if (length <= 0) continue;

                // Inspect IPv4 UDP DNS query
                DnsPacketParser.DnsQueryInfo query = DnsPacketParser.parseDnsQuery(packetBuffer, length);
                if (query == null) {
                    continue; // Skip non-DNS packets
                }

                String domain = query.qName;
                boolean isBlocked = domainFilter.isBlocked(domain);

                if (isBlocked) {
                    // Discreet local sinkhole: synthesize 0.0.0.0 response instantly in 0ms
                    byte[] blockedResponse = DnsPacketParser.buildBlockedDnsResponse(packetBuffer, query);
                    synchronized (out) {
                        out.write(blockedResponse);
                        out.flush();
                    }
                    Log.d(TAG, "Locally filtered wagering domain: " + domain);

                } else {
                    // Legitimate traffic: Dispatch to worker pool asynchronously so in.read() is NEVER blocked!
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
     */
    private void forwardDnsQueryAsync(byte[] packet, int length, DnsPacketParser.DnsQueryInfo query, FileOutputStream out) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            // Protect this socket from being routed back into our own VPN interface
            protect(socket);
            socket.setSoTimeout(1500); // Fast 1.5 second timeout per upstream query

            int dnsPayloadOffset = query.dnsOffset;
            int dnsPayloadLen = length - dnsPayloadOffset;

            // Try resolvers in order until a valid response is received
            for (InetAddress resolver : upstreamResolvers) {
                try {
                    DatagramPacket sendPacket = new DatagramPacket(
                            packet, dnsPayloadOffset, dnsPayloadLen,
                            resolver, DNS_PORT
                    );
                    socket.send(sendPacket);

                    byte[] recvBuffer = new byte[1500];
                    DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length);
                    socket.receive(recvPacket);

                    byte[] forwardedResponse = DnsPacketParser.buildForwardedDnsResponse(
                            recvPacket.getData(), recvPacket.getLength(), query
                    );

                    synchronized (out) {
                        out.write(forwardedResponse);
                        out.flush();
                    }
                    return; // Successfully resolved!

                } catch (IOException ignored) {
                    // Timeout or unreachable on this resolver; try next
                }
            }

        } catch (Exception e) {
            Log.w(TAG, "Error resolving " + query.qName + ": " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        }
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
