package com.bettingshield.app.protection;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;

/**
 * Optional Device Admin Receiver for advanced users who legitimately provision
 * BettingShield via ADB as Device Owner for hardware-level app suspension.
 */
public class ShieldDeviceAdminReceiver extends DeviceAdminReceiver {

    private static final String TAG = "ShieldDeviceAdmin";

    @Override
    public void onEnabled(@NonNull Context context, @NonNull Intent intent) {
        super.onEnabled(context, intent);
        Log.i(TAG, "Device Admin enabled for BettingShield");
    }

    @Override
    public void onDisabled(@NonNull Context context, @NonNull Intent intent) {
        super.onDisabled(context, intent);
        Log.i(TAG, "Device Admin disabled for BettingShield");
    }
}
