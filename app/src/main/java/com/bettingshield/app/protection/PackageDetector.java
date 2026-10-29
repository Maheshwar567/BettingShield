package com.bettingshield.app.protection;

import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import com.bettingshield.app.data.BlockedPackage;
import com.bettingshield.app.data.ProtectionDatabase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages package detection, visibility compliance, and device-owner restriction feasibility.
 */
public class PackageDetector {

    private static final String TAG = "PackageDetector";
    private final Context context;
    private final PackageManager packageManager;
    private final DevicePolicyManager devicePolicyManager;
    private final ComponentName adminComponent;

    public PackageDetector(Context context) {
        this.context = context.getApplicationContext();
        this.packageManager = this.context.getPackageManager();
        this.devicePolicyManager = (DevicePolicyManager) this.context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        this.adminComponent = new ComponentName(this.context, ShieldDeviceAdminReceiver.class);
    }

    /**
     * Checks which verified betting applications are currently installed on this device.
     * Respects Android 11+ package visibility rules via AndroidManifest <queries>.
     */
    public List<BlockedPackage> scanInstalledBettingApps(List<BlockedPackage> verifiedDatabasePackages) {
        List<BlockedPackage> installedBettingApps = new ArrayList<>();
        if (verifiedDatabasePackages == null || verifiedDatabasePackages.isEmpty()) {
            return installedBettingApps;
        }

        for (BlockedPackage pkg : verifiedDatabasePackages) {
            try {
                // In Android 11+ (API 30+), getApplicationInfo will only succeed if the package
                // is listed in <queries> or if the app has special privileges.
                ApplicationInfo info = packageManager.getApplicationInfo(pkg.getPackageName(), 0);
                if (info != null) {
                    installedBettingApps.add(pkg);
                }
            } catch (PackageManager.NameNotFoundException ignored) {
                // App is not installed on this device
            }
        }

        return installedBettingApps;
    }

    /**
     * Verifies if the user has granted Special App Access: Usage Stats.
     */
    public boolean hasUsageAccess() {
        try {
            AppOpsManager appOps = (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
            int mode = appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.getPackageName()
            );
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            Log.e(TAG, "Error checking usage stats permission", e);
            return false;
        }
    }

    /**
     * Determines whether the app has Device Owner or Profile Owner privileges.
     * Note: Standard consumer Android apps DO NOT have Device Owner unless provisioned via ADB
     * or enterprise QR enrollment.
     */
    public boolean isDeviceOwnerActive() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return devicePolicyManager != null && devicePolicyManager.isDeviceOwnerApp(context.getPackageName());
        }
        return false;
    }

    /**
     * Attempts to suspend betting packages if and only if Device Owner privileges are active.
     *
     * @param packagesToSuspend Array of package identifiers to suspend
     * @return Array of packages that could NOT be suspended
     */
    public String[] applyDeviceOwnerSuspension(String[] packagesToSuspend) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && isDeviceOwnerActive()) {
            try {
                // setPackagesSuspended grays out the app in the launcher and prevents launch
                return devicePolicyManager.setPackagesSuspended(adminComponent, packagesToSuspend, true);
            } catch (SecurityException e) {
                Log.e(TAG, "SecurityException while suspending packages: not device owner", e);
            }
        }
        return packagesToSuspend; // Return un-suspended packages
    }
}
