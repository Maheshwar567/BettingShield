package com.bettingshield.app.privacy;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Manages privacy preferences and local application flags.
 * Stored strictly on device; zero tracking, zero telemetry identifiers.
 */
public class PrivacySettings {

    private static final String PREF_NAME = "bettingshield_privacy_prefs";
    private static final String KEY_ONBOARDING_DONE = "onboarding_done";
    private static final String KEY_CONSENT_AGREED = "consent_agreed";
    private static final String KEY_PROTECTION_ENABLED = "protection_enabled";
    private static final String KEY_USAGE_ACCESS_DISMISSED = "usage_dismissed";

    private static volatile PrivacySettings INSTANCE;
    private final SharedPreferences prefs;

    private PrivacySettings(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
    }

    public static PrivacySettings getInstance(Context context) {
        if (INSTANCE == null) {
            synchronized (PrivacySettings.class) {
                if (INSTANCE == null) {
                    INSTANCE = new PrivacySettings(context);
                }
            }
        }
        return INSTANCE;
    }

    public boolean isOnboardingCompleted() {
        return prefs.getBoolean(KEY_ONBOARDING_DONE, false);
    }

    public void setOnboardingCompleted(boolean completed) {
        prefs.edit().putBoolean(KEY_ONBOARDING_DONE, completed).apply();
    }

    public boolean isConsentAgreed() {
        return prefs.getBoolean(KEY_CONSENT_AGREED, false);
    }

    public void setConsentAgreed(boolean agreed) {
        prefs.edit().putBoolean(KEY_CONSENT_AGREED, agreed).apply();
    }

    public boolean isProtectionEnabled() {
        return prefs.getBoolean(KEY_PROTECTION_ENABLED, false);
    }

    public void setProtectionEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_PROTECTION_ENABLED, enabled).apply();
    }

    public boolean isUsageAccessDismissed() {
        return prefs.getBoolean(KEY_USAGE_ACCESS_DISMISSED, false);
    }

    public void setUsageAccessDismissed(boolean dismissed) {
        prefs.edit().putBoolean(KEY_USAGE_ACCESS_DISMISSED, dismissed).apply();
    }
}
