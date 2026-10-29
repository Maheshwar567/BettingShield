package com.bettingshield.app.protection;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
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
import java.net.InetAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Local DNS-filtering VPN Service.
 * Intercepts DNS queries locally on the device and filters known betting domains
 * without routing general payload traffic or storing browsing history.
 */
public class BettingVpnService extends VpnService {

    private static final String TAG = "BettingVpnService";
    public static final String ACTION_START = "com.bettingshield.app.START_VPN";
    public static final String ACTION_STOP = "com.bettingshield.app.STOP_VPN";
    private static final String CHANNEL_ID = "bettingshield_vpn_channel";
    private static final int NOTIFICATION_ID = 1001;

    // Upstream DNS Resolvers (Cloudflare & Google Public DNS)
    private static final String UPSTREAM_DNS_PRIMARY = "1.1.1.1";
    private static final String UPSTREAM_DNS_SECONDARY = "8.8.8.8";
    private static final int DNS_PORT = 53;

    private ParcelFileDescriptor vpnInterface;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private ExecutorService vpnExecutor;

    private DomainFilter domainFilter;

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
            Builder builder = new Builder();
            builder.setSession(getString(R.string.app_name));
            
            // Assign virtual IP to the TUN interface
            builder.addAddress("10.10.10.1", 32);

            // Configure DNS server to route DNS traffic through the local TUN device
            builder.addDnsServer("10.10.10.1");

            // Route only DNS traffic destination to TUN to minimize battery and CPU impact
            builder.addRoute("10.10.10.1", 32);

            builder.setBlocking(true);

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface (null)");
                stopSelf();
                return;
            }

            isRunning.set(true);
            ProtectionManager.getInstance(this).onVpnStateChanged(true);

            vpnExecutor = Executors.newFixedThreadPool(2);
            vpnExecutor.execute(this::runTunReader);

            Log.i(TAG, "BettingShield VPN filtering engine established successfully");

        } catch (Exception e) {
            Log.e(TAG, "Error starting VPN interface", e);
            stopVpn();
            stopSelf();
        }
    }

    private void runTunReader() {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
        byte[] packetBuffer = new byte[32767];

        DatagramSocket upstreamSocket = null;
        try {
            upstreamSocket = new DatagramSocket();
            // Protect this socket from being routed back into our own VPN interface
            protect(upstreamSocket);
            upstreamSocket.setSoTimeout(3000); // 3 second timeout for DNS queries
        } catch (Exception e) {
            Log.e(TAG, "Unable to create protected upstream socket", e);
        }

        InetAddress primaryDns = null;
        InetAddress secondaryDns = null;
        try {
            primaryDns = InetAddress.getByName(UPSTREAM_DNS_PRIMARY);
            secondaryDns = InetAddress.getByName(UPSTREAM_DNS_SECONDARY);
        } catch (Exception ignored) {}

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
                    // Discreet local sinkhole: synthesize 0.0.0.0 or NXDOMAIN
                    byte[] blockedResponse = DnsPacketParser.buildBlockedDnsResponse(packetBuffer, query);
                    synchronized (out) {
                        out.write(blockedResponse);
                        out.flush();
                    }
                    Log.d(TAG, "Locally filtered wagering domain: " + domain);

                } else if (upstreamSocket != null && primaryDns != null) {
                    // Legitimate traffic: Forward DNS payload upstream and return answer to client
                    int dnsPayloadOffset = query.dnsOffset;
                    int dnsPayloadLen = length - dnsPayloadOffset;

                    DatagramPacket sendPacket = new DatagramPacket(
                            packetBuffer, dnsPayloadOffset, dnsPayloadLen,
                            primaryDns, DNS_PORT
                    );

                    upstreamSocket.send(sendPacket);

                    byte[] recvBuffer = new byte[1500];
                    DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length);
                    
                    try {
                        upstreamSocket.receive(recvPacket);

                        byte[] forwardedResponse = DnsPacketParser.buildForwardedDnsResponse(
                                recvPacket.getData(), recvPacket.getLength(), query
                        );

                        synchronized (out) {
                            out.write(forwardedResponse);
                            out.flush();
                        }
                    } catch (IOException timeoutEx) {
                        // Retry with secondary DNS if primary timed out
                        if (secondaryDns != null) {
                            sendPacket.setAddress(secondaryDns);
                            upstreamSocket.send(sendPacket);
                            upstreamSocket.receive(recvPacket);
                            byte[] forwardedResponse = DnsPacketParser.buildForwardedDnsResponse(
                                    recvPacket.getData(), recvPacket.getLength(), query
                            );
                            synchronized (out) {
                                out.write(forwardedResponse);
                                out.flush();
                            }
                        }
                    }
                }

            } catch (Exception e) {
                if (!isRunning.get()) break;
                Log.w(TAG, "Error processing DNS packet: " + e.getMessage());
            }
        }

        if (upstreamSocket != null && !upstreamSocket.isClosed()) {
            upstreamSocket.close();
        }

        try {
            in.close();
            out.close();
        } catch (IOException ignored) {}
    }

    private synchronized void stopVpn() {
        isRunning.set(false);
        if (vpnExecutor != null) {
            vpnExecutor.shutdownNow();
            vpnExecutor = null;
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                Log.e(TAG, "Error closing VPN descriptor", e);
            }
            vpnInterface = null;
        }

        ProtectionManager.getInstance(this).onVpnStateChanged(false);
        Log.i(TAG, "BettingShield VPN filtering engine stopped");
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
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Intent stopIntent = new Intent(this, BettingVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(
                this, 1, stopIntent,
                PendingIntent.FLAG_IMMUTABLE
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.notification_title))
                .setContentText(getString(R.string.notification_text))
                .setSmallIcon(R.drawable.ic_shield)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .addAction(0, getString(R.string.action_pause), stopPendingIntent)
                .build();
    }
}
