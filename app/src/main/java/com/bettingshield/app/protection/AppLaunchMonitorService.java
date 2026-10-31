package com.bettingshield.app.protection;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.bettingshield.app.R;
import com.bettingshield.app.data.BlockedPackage;
import com.bettingshield.app.data.ProtectionDatabase;
import com.bettingshield.app.ui.InterventionActivity;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Monitors foreground application changes via UsageStatsManager to present
 * a discreet mindful pause screen if a user opens a known wagering application.
 */
public class AppLaunchMonitorService extends Service {

    private static final String TAG = "AppLaunchMonitor";
    private static final String CHANNEL_ID = "bettingshield_monitor_channel";
    private static final int NOTIFICATION_ID = 1002;
    private static final long POLL_INTERVAL_MS = 1500;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final Set<String> watchedPackages = Collections.synchronizedSet(new HashSet<>());
    private String lastReportedPackage = "";
    private long lastCheckTimestamp = 0;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        loadWatchedPackages();
    }

    private void loadWatchedPackages() {
        ProtectionDatabase.databaseWriteExecutor.execute(() -> {
            List<BlockedPackage> packages = ProtectionDatabase.getDatabase(this)
                    .protectionDao()
                    .getAllBlockedPackages();
            synchronized (watchedPackages) {
                watchedPackages.clear();
                for (BlockedPackage pkg : packages) {
                    watchedPackages.add(pkg.getPackageName());
                }
            }
        });
    }

    public static void reloadWatchedPackages(Context context) {
        try {
            Intent intent = new Intent(context, AppLaunchMonitorService.class);
            intent.setAction("com.bettingshield.app.RELOAD_PACKAGES");
            context.startService(intent);
        } catch (Exception ignored) {}
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "com.bettingshield.app.RELOAD_PACKAGES".equals(intent.getAction())) {
            loadWatchedPackages();
            return START_STICKY;
        }

        startForeground(NOTIFICATION_ID, buildNotification());
        loadWatchedPackages();
        if (!isRunning.get()) {
            isRunning.set(true);
            lastCheckTimestamp = System.currentTimeMillis();
            handler.post(checkRunnable);
        }
        return START_STICKY;
    }

    private final Runnable checkRunnable = new Runnable() {
        @Override
        public void run() {
            if (!isRunning.get()) return;

            checkForegroundApp();
            handler.postDelayed(this, POLL_INTERVAL_MS);
        }
    };

    private void checkForegroundApp() {
        UsageStatsManager usageStatsManager = (UsageStatsManager) getSystemService(Context.USAGE_STATS_SERVICE);
        if (usageStatsManager == null) return;

        long now = System.currentTimeMillis();
        UsageEvents events = usageStatsManager.queryEvents(lastCheckTimestamp, now);
        lastCheckTimestamp = now;

        if (events == null) return;

        UsageEvents.Event event = new UsageEvents.Event();
        String currentForegroundPackage = null;

        while (events.hasNextEvent()) {
            events.getNextEvent(event);
            if (event.getEventType() == UsageEvents.Event.ACTIVITY_RESUMED) {
                currentForegroundPackage = event.getPackageName();
            }
        }

        if (currentForegroundPackage != null && !currentForegroundPackage.equals(getPackageName())) {
            if (watchedPackages.contains(currentForegroundPackage)) {
                if (!currentForegroundPackage.equals(lastReportedPackage)) {
                    lastReportedPackage = currentForegroundPackage;
                    launchIntervention(currentForegroundPackage);
                }
            } else {
                lastReportedPackage = currentForegroundPackage;
            }
        }
    }

    private void launchIntervention(String targetPackage) {
        Intent intent = new Intent(this, InterventionActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        intent.putExtra("target_package", targetPackage);
        startActivity(intent);
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "App Monitor Service",
                    NotificationManager.IMPORTANCE_MIN
            );
            channel.setShowBadge(false);
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.notification_title))
                .setContentText("Discreet application protection is active")
                .setSmallIcon(R.drawable.ic_shield)
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .build();
    }

    @Override
    public void onDestroy() {
        isRunning.set(false);
        handler.removeCallbacks(checkRunnable);
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
