package com.bettingshield.app.protection;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.bettingshield.app.data.BlockedDomain;
import com.bettingshield.app.data.ProtectionDatabase;
import com.bettingshield.app.privacy.PrivacySettings;

import java.util.ArrayList;
import java.util.List;

/**
 * High-level coordinator managing protection state, VPN service lifecycle,
 * and rule synchronisation between Room database and DomainFilter engine.
 */
public class ProtectionManager {

    private static volatile ProtectionManager INSTANCE;
    private final Context context;
    private final DomainFilter domainFilter;
    private final PackageDetector packageDetector;
    private final MutableLiveData<Boolean> isProtectionActive = new MutableLiveData<>(false);

    private ProtectionManager(Context context) {
        this.context = context.getApplicationContext();
        this.domainFilter = new DomainFilter();
        this.packageDetector = new PackageDetector(this.context);
        reloadRulesFromDatabase();
    }

    public static ProtectionManager getInstance(Context context) {
        if (INSTANCE == null) {
            synchronized (ProtectionManager.class) {
                if (INSTANCE == null) {
                    INSTANCE = new ProtectionManager(context);
                }
            }
        }
        return INSTANCE;
    }

    public DomainFilter getDomainFilter() {
        return domainFilter;
    }

    public PackageDetector getPackageDetector() {
        return packageDetector;
    }

    public LiveData<Boolean> isProtectionActiveLiveData() {
        return isProtectionActive;
    }

    public boolean isProtectionActive() {
        Boolean value = isProtectionActive.getValue();
        return value != null && value;
    }

    public void onVpnStateChanged(boolean active) {
        isProtectionActive.postValue(active);
        PrivacySettings.getInstance(context).setProtectionEnabled(active);
    }

    /**
     * Loads blocked domains and allowlist exceptions from Room into DomainFilter.
     */
    public void reloadRulesFromDatabase() {
        ProtectionDatabase.databaseWriteExecutor.execute(() -> {
            ProtectionDatabase db = ProtectionDatabase.getDatabase(context);
            List<BlockedDomain> blockedList = db.protectionDao().getAllBlockedDomains();
            List<BlockedDomain> allowedList = db.protectionDao().getAllAllowedExceptions();

            List<String> blocked = new ArrayList<>();
            for (BlockedDomain bd : blockedList) {
                blocked.add(bd.getDomain());
            }

            List<String> allowed = new ArrayList<>();
            for (BlockedDomain ad : allowedList) {
                allowed.add(ad.getDomain());
            }

            domainFilter.setBlockedDomains(blocked);
            domainFilter.setAllowedExceptions(allowed);
            AppLaunchMonitorService.reloadWatchedPackages(context);
        });
    }

    /**
     * Prepares and starts the VPN protection service.
     * If VPN permission is not yet granted, returns the intent required for startActivityForResult.
     */
    public Intent prepareVpn(Activity activity) {
        return VpnService.prepare(activity);
    }

    public void startProtectionService() {
        reloadRulesFromDatabase();

        Intent vpnIntent = new Intent(context, BettingVpnService.class);
        vpnIntent.setAction(BettingVpnService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(vpnIntent);
        } else {
            context.startService(vpnIntent);
        }

        // Start optional App Launch Monitor if usage stats permission was granted
        if (packageDetector.hasUsageAccess()) {
            Intent monitorIntent = new Intent(context, AppLaunchMonitorService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(monitorIntent);
            } else {
                context.startService(monitorIntent);
            }
        }
    }

    public void stopProtectionService() {
        Intent vpnIntent = new Intent(context, BettingVpnService.class);
        vpnIntent.setAction(BettingVpnService.ACTION_STOP);
        context.startService(vpnIntent);

        Intent monitorIntent = new Intent(context, AppLaunchMonitorService.class);
        context.stopService(monitorIntent);

        onVpnStateChanged(false);
    }
}
