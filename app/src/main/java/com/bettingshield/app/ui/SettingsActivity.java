package com.bettingshield.app.ui;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.bettingshield.app.R;
import com.bettingshield.app.data.BlockedDomain;
import com.bettingshield.app.data.BlockedPackage;
import com.bettingshield.app.data.ProtectionDao;
import com.bettingshield.app.data.ProtectionDatabase;
import com.bettingshield.app.protection.DomainFilter;
import com.bettingshield.app.protection.ProtectionManager;
import com.bettingshield.app.updates.RuleUpdateWorker;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Mobile Master Admin Console.
 * Protected by Master Admin PIN (8888).
 * Allows the administrator to add/remove blocked sites, add/remove blocked apps,
 * select apps from the phone to block, and sync rules across all devices.
 */
public class SettingsActivity extends AppCompatActivity {

    private static final String ADMIN_PIN = "8888";
    private static final String HUB_API_URL = "http://192.168.31.186:8085";

    // UI elements
    private TextInputEditText etDomain;
    private MaterialButton btnAddDomain;
    private TextView tvDomainCountBadge;
    private RecyclerView rvBlockedDomains;
    private BlockedDomainsAdapter domainsAdapter;

    private TextInputEditText etAppName;
    private TextInputEditText etPackageName;
    private MaterialButton btnAddPackage;
    private MaterialButton btnPickInstalledApp;
    private TextView tvPackageCountBadge;
    private RecyclerView rvBlockedPackages;
    private BlockedPackagesAdapter packagesAdapter;

    private TextView tvUsageAccessState;
    private MaterialButton btnGrantUsageAccess;
    private MaterialButton btnSyncWithHub;
    private MaterialButton btnResetRules;

    private ProtectionManager protectionManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        protectionManager = ProtectionManager.getInstance(this);

        // Security gate: Prompt for Master Admin PIN
        promptAdminPin();
    }

    private void promptAdminPin() {
        EditText pinInput = new EditText(this);
        pinInput.setInputType(android.text.InputType.TYPE_CLASS_NUMBER | android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pinInput.setHint("Enter 4-digit Master PIN (8888)");
        pinInput.setTextAlignment(View.TEXT_ALIGNMENT_CENTER);
        pinInput.setTextSize(20);

        new AlertDialog.Builder(this)
                .setTitle("🔒 Master Admin Authentication")
                .setMessage("Enter Admin PIN to manage blocked betting sites and applications on mobile.")
                .setView(pinInput)
                .setCancelable(false)
                .setPositiveButton("Unlock", (dialog, which) -> {
                    String entered = pinInput.getText().toString().trim();
                    if (ADMIN_PIN.equals(entered)) {
                        initAdminUi();
                    } else {
                        Toast.makeText(this, "Incorrect Admin PIN. Access Denied.", Toast.LENGTH_SHORT).show();
                        finish();
                    }
                })
                .setNegativeButton("Cancel", (dialog, which) -> finish())
                .show();
    }

    private void initAdminUi() {
        setContentView(R.layout.activity_settings);

        ImageButton btnBack = findViewById(R.id.btnBack);
        btnBack.setOnClickListener(v -> finish());

        // Domain views
        etDomain = findViewById(R.id.etDomain);
        btnAddDomain = findViewById(R.id.btnAddDomain);
        tvDomainCountBadge = findViewById(R.id.tvDomainCountBadge);
        rvBlockedDomains = findViewById(R.id.rvBlockedDomains);

        // Package views
        etAppName = findViewById(R.id.etAppName);
        etPackageName = findViewById(R.id.etPackageName);
        btnAddPackage = findViewById(R.id.btnAddPackage);
        btnPickInstalledApp = findViewById(R.id.btnPickInstalledApp);
        tvPackageCountBadge = findViewById(R.id.tvPackageCountBadge);
        rvBlockedPackages = findViewById(R.id.rvBlockedPackages);

        // Controls
        tvUsageAccessState = findViewById(R.id.tvUsageAccessState);
        btnGrantUsageAccess = findViewById(R.id.btnGrantUsageAccess);
        btnSyncWithHub = findViewById(R.id.btnSyncWithHub);
        btnResetRules = findViewById(R.id.btnResetRules);

        setupRecyclerViews();
        observeDatabaseData();

        btnAddDomain.setOnClickListener(v -> addBlockedDomain());
        btnAddPackage.setOnClickListener(v -> addBlockedPackage());
        btnPickInstalledApp.setOnClickListener(v -> showInstalledAppsPicker());
        btnSyncWithHub.setOnClickListener(v -> triggerHubSync());
        btnResetRules.setOnClickListener(v -> confirmResetRules());
        btnGrantUsageAccess.setOnClickListener(v -> openUsageSettings());

        updateUsageAccessUI();
    }

    private void setupRecyclerViews() {
        // Domains Adapter
        domainsAdapter = new BlockedDomainsAdapter(domain -> {
            ProtectionDatabase.databaseWriteExecutor.execute(() -> {
                ProtectionDatabase.getDatabase(this).protectionDao().deleteDomain(domain);
                protectionManager.reloadRulesFromDatabase();
                notifyHubDeleteDomain(domain.getDomain());
            });
            Toast.makeText(this, "Unblocked: " + domain.getDomain(), Toast.LENGTH_SHORT).show();
        });
        rvBlockedDomains.setLayoutManager(new LinearLayoutManager(this));
        rvBlockedDomains.setAdapter(domainsAdapter);

        // Packages Adapter
        packagesAdapter = new BlockedPackagesAdapter(pkg -> {
            ProtectionDatabase.databaseWriteExecutor.execute(() -> {
                ProtectionDatabase.getDatabase(this).protectionDao().deletePackage(pkg.getPackageName());
                protectionManager.reloadRulesFromDatabase();
            });
            Toast.makeText(this, "Removed from blocked apps: " + pkg.getAppName(), Toast.LENGTH_SHORT).show();
        });
        rvBlockedPackages.setLayoutManager(new LinearLayoutManager(this));
        rvBlockedPackages.setAdapter(packagesAdapter);
    }

    private void observeDatabaseData() {
        ProtectionDao dao = ProtectionDatabase.getDatabase(this).protectionDao();

        // Observe Blocked Domains
        dao.getAllBlockedDomainsLiveData().observe(this, domains -> {
            if (domains != null) {
                domainsAdapter.setDomains(domains);
                tvDomainCountBadge.setText(domains.size() + " sites");
            }
        });

        // Observe Blocked Packages
        dao.getAllBlockedPackagesLiveData().observe(this, packages -> {
            if (packages != null) {
                packagesAdapter.setPackages(packages);
                tvPackageCountBadge.setText(packages.size() + " apps");
            }
        });
    }

    private void addBlockedDomain() {
        String input = etDomain.getText() != null ? etDomain.getText().toString().trim() : "";
        String normalized = DomainFilter.normalizeHost(input);

        if (normalized.isEmpty() || !normalized.contains(".")) {
            Toast.makeText(this, "Enter a valid website (e.g. playveer.com)", Toast.LENGTH_SHORT).show();
            return;
        }

        ProtectionDatabase.databaseWriteExecutor.execute(() -> {
            BlockedDomain bd = new BlockedDomain(
                    normalized,
                    "admin_added",
                    false, // is_allowed = false (Blocked)
                    System.currentTimeMillis()
            );
            ProtectionDatabase.getDatabase(this).protectionDao().insertDomain(bd);
            protectionManager.reloadRulesFromDatabase();
            notifyHubAddDomain(normalized);
        });

        etDomain.setText("");
        Toast.makeText(this, "Website Blocked: " + normalized, Toast.LENGTH_SHORT).show();
    }

    private void addBlockedPackage() {
        String appName = etAppName.getText() != null ? etAppName.getText().toString().trim() : "";
        String pkg = etPackageName.getText() != null ? etPackageName.getText().toString().trim() : "";

        if (pkg.isEmpty() || !pkg.contains(".")) {
            Toast.makeText(this, "Enter valid package name (e.g. com.bet365)", Toast.LENGTH_SHORT).show();
            return;
        }

        if (appName.isEmpty()) {
            appName = pkg;
        }

        final String finalAppName = appName;
        ProtectionDatabase.databaseWriteExecutor.execute(() -> {
            BlockedPackage bp = new BlockedPackage(
                    pkg,
                    finalAppName,
                    "admin_added_wagering",
                    System.currentTimeMillis()
            );
            ProtectionDatabase.getDatabase(this).protectionDao().insertPackage(bp);
            protectionManager.reloadRulesFromDatabase();
            notifyHubAddPackage(pkg, finalAppName);
        });

        etAppName.setText("");
        etPackageName.setText("");
        Toast.makeText(this, "App Blocked: " + finalAppName, Toast.LENGTH_SHORT).show();
    }

    private void showInstalledAppsPicker() {
        PackageManager pm = getPackageManager();
        List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);

        List<AppEntry> userApps = new ArrayList<>();
        for (ApplicationInfo info : apps) {
            // Exclude our own app and core system apps that are not launchable
            if (info.packageName.equals(getPackageName())) continue;
            if (pm.getLaunchIntentForPackage(info.packageName) != null) {
                String label = pm.getApplicationLabel(info).toString();
                userApps.add(new AppEntry(label, info.packageName));
            }
        }

        Collections.sort(userApps, (a, b) -> a.name.compareToIgnoreCase(b.name));

        String[] displayNames = new String[userApps.size()];
        for (int i = 0; i < userApps.size(); i++) {
            displayNames[i] = userApps.get(i).name + " (" + userApps.get(i).packageName + ")";
        }

        new AlertDialog.Builder(this)
                .setTitle("Select App on Phone to Block")
                .setItems(displayNames, (dialog, which) -> {
                    AppEntry selected = userApps.get(which);
                    etAppName.setText(selected.name);
                    etPackageName.setText(selected.packageName);
                    addBlockedPackage();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private static class AppEntry {
        String name;
        String packageName;
        AppEntry(String name, String packageName) {
            this.name = name;
            this.packageName = packageName;
        }
    }

    private void triggerHubSync() {
        Toast.makeText(this, "Pulling latest rules from hub...", Toast.LENGTH_SHORT).show();
        ProtectionDatabase.databaseWriteExecutor.execute(() -> {
            RuleUpdateWorker.syncDirect(getApplicationContext());
            runOnUiThread(() -> Toast.makeText(this, "Rules synced successfully!", Toast.LENGTH_SHORT).show());
        });
    }

    private void confirmResetRules() {
        new AlertDialog.Builder(this)
                .setTitle("Reset to Default Rules")
                .setMessage("Restore factory default verified wagering blocklist?")
                .setPositiveButton("Reset", (dialog, which) -> {
                    ProtectionDatabase.databaseWriteExecutor.execute(() -> {
                        ProtectionDatabase.getDatabase(this).clearAllTables();
                        // Re-trigger database seeding
                        ProtectionDatabase.getDatabase(this).protectionDao().getBlockedDomainCount();
                        protectionManager.reloadRulesFromDatabase();
                        runOnUiThread(() -> Toast.makeText(this, "Factory blocklist restored", Toast.LENGTH_SHORT).show());
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void openUsageSettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Could not open settings", Toast.LENGTH_SHORT).show();
        }
    }

    private void updateUsageAccessUI() {
        boolean hasUsage = protectionManager.getPackageDetector().hasUsageAccess();
        if (hasUsage) {
            tvUsageAccessState.setText("✅ App Launch Blocker Active: Watching for restricted apps");
            tvUsageAccessState.setTextColor(getColor(R.color.status_protected));
            btnGrantUsageAccess.setEnabled(false);
            btnGrantUsageAccess.setText("App Guard Granted");
        } else {
            tvUsageAccessState.setText("⚠️ Usage Access Required to detect when betting apps are opened");
            tvUsageAccessState.setTextColor(getColor(R.color.status_paused));
            btnGrantUsageAccess.setEnabled(true);
            btnGrantUsageAccess.setText("Enable App Guard (Usage Access)");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (tvUsageAccessState != null) {
            updateUsageAccessUI();
        }
    }

    // Network background helpers to notify web hub
    private void notifyHubAddDomain(String domain) {
        new Thread(() -> {
            try {
                URL url = new URL(HUB_API_URL + "/api/admin/add-domain");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer bettingshield-admin-token-secure-8888");
                conn.setDoOutput(true);
                conn.setConnectTimeout(3000);
                JSONObject obj = new JSONObject();
                obj.put("domain", domain);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(obj.toString().getBytes());
                }
                conn.getResponseCode();
                conn.disconnect();
            } catch (Exception ignored) {}
        }).start();
    }

    private void notifyHubDeleteDomain(String domain) {
        new Thread(() -> {
            try {
                URL url = new URL(HUB_API_URL + "/api/admin/delete-domain");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer bettingshield-admin-token-secure-8888");
                conn.setDoOutput(true);
                conn.setConnectTimeout(3000);
                JSONObject obj = new JSONObject();
                obj.put("domain", domain);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(obj.toString().getBytes());
                }
                conn.getResponseCode();
                conn.disconnect();
            } catch (Exception ignored) {}
        }).start();
    }

    private void notifyHubAddPackage(String pkg, String name) {
        new Thread(() -> {
            try {
                URL url = new URL(HUB_API_URL + "/api/admin/add-package");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer bettingshield-admin-token-secure-8888");
                conn.setDoOutput(true);
                conn.setConnectTimeout(3000);
                JSONObject obj = new JSONObject();
                obj.put("packageName", pkg);
                obj.put("name", name);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(obj.toString().getBytes());
                }
                conn.getResponseCode();
                conn.disconnect();
            } catch (Exception ignored) {}
        }).start();
    }
}
