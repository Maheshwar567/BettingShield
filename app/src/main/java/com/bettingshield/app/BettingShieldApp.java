package com.bettingshield.app;

import android.app.Application;
import android.util.Log;

import com.bettingshield.app.data.ProtectionDatabase;
import com.bettingshield.app.privacy.PrivacySettings;
import com.bettingshield.app.protection.ProtectionManager;
import com.bettingshield.app.updates.RuleUpdateWorker;

/**
 * Main Application class for BettingShield.
 * Initializes offline database and schedules periodic background updates.
 */
public class BettingShieldApp extends Application {

    private static final String TAG = "BettingShieldApp";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Initializing BettingShield Application...");

        // Eagerly initialize local database and protection engine
        ProtectionDatabase.getDatabase(this);
        ProtectionManager.getInstance(this);

        // Schedule periodic blocklist updates via WorkManager
        RuleUpdateWorker.schedulePeriodicUpdates(this);

        // Resume protection if previously active
        if (PrivacySettings.getInstance(this).isProtectionEnabled()) {
            ProtectionManager.getInstance(this).startProtectionService();
        }
    }
}
