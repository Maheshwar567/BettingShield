package com.bettingshield.app.updates;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Constraints;
import androidx.work.NetworkType;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.bettingshield.app.data.BlockedDomain;
import com.bettingshield.app.data.BlockedPackage;
import com.bettingshield.app.data.BlocklistMeta;
import com.bettingshield.app.data.ProtectionDao;
import com.bettingshield.app.data.ProtectionDatabase;
import com.bettingshield.app.protection.ProtectionManager;
import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Background WorkManager Worker responsible for securely checking and applying
 * signed blocklist updates over HTTPS without requiring user interaction.
 */
public class RuleUpdateWorker extends Worker {

    private static final String TAG = "RuleUpdateWorker";
    private static final String WORK_NAME = "bettingshield_rule_update";
    
    // Secure HTTPS endpoint for signed rule updates (e.g. Supabase storage / CDN)
    private static final String DEFAULT_UPDATE_URL = "https://updates.bettingshield.org/v1/rules.json";

    public RuleUpdateWorker(@NonNull Context context, @NonNull WorkerParameters workerParams) {
        super(context, workerParams);
    }

    @NonNull
    @Override
    public Result doWork() {
        Log.i(TAG, "Starting periodic blocklist update check...");
        Context context = getApplicationContext();
        ProtectionDatabase db = ProtectionDatabase.getDatabase(context);
        ProtectionDao dao = db.protectionDao();

        try {
            BlocklistMeta currentMeta = dao.getMeta("active_rules");
            int currentVersion = (currentMeta != null) ? currentMeta.getVersion() : 0;

            String jsonPayload = fetchRulesJson(DEFAULT_UPDATE_URL);
            if (jsonPayload == null || jsonPayload.trim().isEmpty()) {
                Log.w(TAG, "No update received from server or server unavailable");
                return Result.retry();
            }

            Gson gson = new Gson();
            BlocklistPayload payload = gson.fromJson(jsonPayload, BlocklistPayload.class);

            // Cryptographic Verification & Anti-Rollback Check
            boolean isAuthentic = SignatureVerifier.verify(payload, currentVersion);
            if (!isAuthentic) {
                Log.e(TAG, "Update signature verification failed or older version encountered. Aborting.");
                return Result.failure();
            }

            // Apply updates atomically to local Room database
            long now = System.currentTimeMillis();
            List<BlockedDomain> newDomains = new ArrayList<>();
            for (String domain : payload.getDomains()) {
                newDomains.add(new BlockedDomain(domain, "synced_wagering", false, now));
            }

            List<BlockedPackage> newPackages = new ArrayList<>();
            if (payload.getPackages() != null) {
                for (BlocklistPayload.PackageEntry entry : payload.getPackages()) {
                    newPackages.add(new BlockedPackage(
                            entry.getPackageName(),
                            entry.getAppName(),
                            entry.getCategory(),
                            now
                    ));
                }
            }

            db.runInTransaction(() -> {
                dao.clearSyncedBlockedDomains();
                dao.insertDomains(newDomains);

                if (!newPackages.isEmpty()) {
                    dao.clearPackages();
                    dao.insertPackages(newPackages);
                }

                dao.insertMeta(new BlocklistMeta(
                        "active_rules",
                        payload.getVersion(),
                        payload.getTimestamp(),
                        payload.getSignature()
                ));
            });

            // Reload rules into in-memory engine
            ProtectionManager.getInstance(context).reloadRulesFromDatabase();
            Log.i(TAG, "Successfully updated blocklist to version " + payload.getVersion());
            return Result.success();

        } catch (Exception e) {
            Log.e(TAG, "Exception during rule update check", e);
            return Result.retry();
        }
    }

    private String fetchRulesJson(String urlString) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(urlString);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setRequestProperty("User-Agent", "BettingShield-Client/1.0");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                reader.close();
                return sb.toString();
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not fetch rules from " + urlString + ": " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return null;
    }

    /**
     * Schedules periodic background update check via WorkManager.
     */
    public static void schedulePeriodicUpdates(Context context) {
        Constraints constraints = new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build();

        PeriodicWorkRequest updateRequest =
                new PeriodicWorkRequest.Builder(RuleUpdateWorker.class, 24, TimeUnit.HOURS)
                        .setConstraints(constraints)
                        .build();

        WorkManager.getInstance(context).enqueue(updateRequest);
        Log.i(TAG, "Scheduled 24-hour periodic update worker");
    }
}
