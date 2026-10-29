package com.bettingshield.app.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.bettingshield.app.R;
import com.bettingshield.app.privacy.PrivacySettings;
import com.bettingshield.app.protection.ProtectionManager;
import com.google.android.material.button.MaterialButton;

/**
 * Handles explicit system permission requests:
 * 1. VpnService.prepare() for local DNS filter.
 * 2. Optional Usage Access for foreground app detection.
 */
public class SetupActivity extends AppCompatActivity {

    private TextView tvVpnStatus;
    private TextView tvUsageStatus;
    private MaterialButton btnAuthorizeVpn;
    private MaterialButton btnGrantUsage;
    private MaterialButton btnFinishSetup;

    private ProtectionManager protectionManager;

    private final ActivityResultLauncher<Intent> vpnLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK) {
                    updateVpnStatusUI(true);
                    protectionManager.startProtectionService();
                } else {
                    updateVpnStatusUI(false);
                    Toast.makeText(this, "VPN authorization is required to filter websites", Toast.LENGTH_SHORT).show();
                }
            }
    );

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);

        protectionManager = ProtectionManager.getInstance(this);

        tvVpnStatus = findViewById(R.id.tvVpnStatus);
        tvUsageStatus = findViewById(R.id.tvUsageStatus);
        btnAuthorizeVpn = findViewById(R.id.btnAuthorizeVpn);
        btnGrantUsage = findViewById(R.id.btnGrantUsage);
        btnFinishSetup = findViewById(R.id.btnFinishSetup);

        btnAuthorizeVpn.setOnClickListener(v -> requestVpnAuthorization());
        btnGrantUsage.setOnClickListener(v -> requestUsageAccess());

        btnFinishSetup.setOnClickListener(v -> {
            PrivacySettings.getInstance(this).setOnboardingCompleted(true);
            Intent intent = new Intent(SetupActivity.this, MainActivity.class);
            startActivity(intent);
            finish();
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkPermissionsState();
    }

    private void checkPermissionsState() {
        // Check VPN preparation state
        Intent prepareIntent = VpnService.prepare(this);
        updateVpnStatusUI(prepareIntent == null);

        // Check Usage Access state
        boolean hasUsage = protectionManager.getPackageDetector().hasUsageAccess();
        updateUsageStatusUI(hasUsage);
    }

    private void requestVpnAuthorization() {
        Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent != null) {
            vpnLauncher.launch(prepareIntent);
        } else {
            // Already authorized
            updateVpnStatusUI(true);
            protectionManager.startProtectionService();
            Toast.makeText(this, "Protection Filter Authorized", Toast.LENGTH_SHORT).show();
        }
    }

    private void requestUsageAccess() {
        try {
            Intent intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Could not open settings", Toast.LENGTH_SHORT).show();
        }
    }

    private void updateVpnStatusUI(boolean authorized) {
        if (authorized) {
            tvVpnStatus.setText(R.string.status_granted);
            tvVpnStatus.setTextColor(getColor(R.color.status_protected));
            btnAuthorizeVpn.setEnabled(false);
            btnAuthorizeVpn.setText("Authorized");
        } else {
            tvVpnStatus.setText(R.string.status_not_granted);
            tvVpnStatus.setTextColor(getColor(R.color.status_paused));
            btnAuthorizeVpn.setEnabled(true);
            btnAuthorizeVpn.setText(R.string.setup_vpn_btn);
        }
    }

    private void updateUsageStatusUI(boolean granted) {
        if (granted) {
            tvUsageStatus.setText(R.string.status_granted);
            tvUsageStatus.setTextColor(getColor(R.color.status_protected));
            btnGrantUsage.setEnabled(false);
            btnGrantUsage.setText("Access Granted");
        } else {
            tvUsageStatus.setText(R.string.status_not_granted);
            tvUsageStatus.setTextColor(getColor(R.color.secondary));
            btnGrantUsage.setEnabled(true);
            btnGrantUsage.setText(R.string.setup_usage_btn);
        }
    }
}
