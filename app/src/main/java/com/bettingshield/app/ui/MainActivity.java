package com.bettingshield.app.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;

import com.bettingshield.app.R;
import com.bettingshield.app.data.BlocklistMeta;
import com.bettingshield.app.data.ProtectionDatabase;
import com.bettingshield.app.privacy.PrivacySettings;
import com.bettingshield.app.protection.ProtectionManager;
import com.bettingshield.app.updates.RuleUpdateWorker;
import com.google.android.material.button.MaterialButton;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Main Status Dashboard for BettingShield.
 */
public class MainActivity extends AppCompatActivity {

    private CardView cardStatus;
    private ImageView ivStatusShield;
    private TextView tvStatusTitle;
    private TextView tvStatusSubtitle;
    private MaterialButton btnToggleProtection;
    private TextView tvDomainCount;
    private TextView tvPackageCount;
    private TextView tvVersionLabel;
    private TextView tvUpdateStatus;
    private MaterialButton btnCheckUpdates;
    private ImageButton btnSettings;

    private ProtectionManager protectionManager;

    private final ActivityResultLauncher<Intent> vpnLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK) {
                    protectionManager.startProtectionService();
                } else {
                    Toast.makeText(this, "VPN permission is needed to start protection", Toast.LENGTH_SHORT).show();
                }
            }
    );

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Check if onboarding was completed
        if (!PrivacySettings.getInstance(this).isOnboardingCompleted()) {
            Intent welcomeIntent = new Intent(this, WelcomeActivity.class);
            startActivity(welcomeIntent);
            finish();
            return;
        }

        setContentView(R.layout.activity_main);
        protectionManager = ProtectionManager.getInstance(this);

        initViews();
        observeProtectionState();
        observeDatabaseCounts();
    }

    private void initViews() {
        cardStatus = findViewById(R.id.cardStatus);
        ivStatusShield = findViewById(R.id.ivStatusShield);
        tvStatusTitle = findViewById(R.id.tvStatusTitle);
        tvStatusSubtitle = findViewById(R.id.tvStatusSubtitle);
        btnToggleProtection = findViewById(R.id.btnToggleProtection);
        tvDomainCount = findViewById(R.id.tvDomainCount);
        tvPackageCount = findViewById(R.id.tvPackageCount);
        tvVersionLabel = findViewById(R.id.tvVersionLabel);
        tvUpdateStatus = findViewById(R.id.tvUpdateStatus);
        btnCheckUpdates = findViewById(R.id.btnCheckUpdates);
        btnSettings = findViewById(R.id.btnSettings);

        btnToggleProtection.setOnClickListener(v -> toggleProtection());

        btnCheckUpdates.setOnClickListener(v -> triggerManualUpdateCheck());

        btnSettings.setOnClickListener(v -> {
            Intent intent = new Intent(MainActivity.this, SettingsActivity.class);
            startActivity(intent);
        });
    }

    private void toggleProtection() {
        if (protectionManager.isProtectionActive()) {
            protectionManager.stopProtectionService();
        } else {
            Intent prepareIntent = VpnService.prepare(this);
            if (prepareIntent != null) {
                vpnLauncher.launch(prepareIntent);
            } else {
                protectionManager.startProtectionService();
            }
        }
    }

    private void observeProtectionState() {
        protectionManager.isProtectionActiveLiveData().observe(this, active -> {
            if (active != null && active) {
                cardStatus.setCardBackgroundColor(getColor(R.color.status_protected_bg));
                ivStatusShield.setImageResource(R.drawable.ic_shield_check);
                tvStatusTitle.setText(R.string.status_active_title);
                tvStatusTitle.setTextColor(getColor(R.color.status_protected));
                tvStatusSubtitle.setText(R.string.status_active_subtitle);
                btnToggleProtection.setText(R.string.action_pause);
            } else {
                cardStatus.setCardBackgroundColor(getColor(R.color.status_paused_bg));
                ivStatusShield.setImageResource(R.drawable.ic_shield_alert);
                tvStatusTitle.setText(R.string.status_inactive_title);
                tvStatusTitle.setTextColor(getColor(R.color.status_paused));
                tvStatusSubtitle.setText(R.string.status_inactive_subtitle);
                btnToggleProtection.setText(R.string.action_resume);
            }
        });
    }

    private void observeDatabaseCounts() {
        ProtectionDatabase db = ProtectionDatabase.getDatabase(this);

        db.protectionDao().getBlockedDomainCountLiveData().observe(this, count -> {
            if (count != null) {
                tvDomainCount.setText(String.valueOf(count));
            }
        });

        db.protectionDao().getBlockedPackageCountLiveData().observe(this, count -> {
            if (count != null) {
                tvPackageCount.setText(String.valueOf(count));
            }
        });

        db.protectionDao().getMetaLiveData("active_rules").observe(this, meta -> {
            if (meta != null) {
                String dateStr = new SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
                        .format(new Date(meta.getLastUpdated()));
                tvVersionLabel.setText(getString(R.string.rules_version_label, meta.getVersion(), dateStr));
            }
        });
    }

    private void triggerManualUpdateCheck() {
        tvUpdateStatus.setText(R.string.loading);
        btnCheckUpdates.setEnabled(false);

        OneTimeWorkRequest updateWork = new OneTimeWorkRequest.Builder(RuleUpdateWorker.class).build();
        WorkManager.getInstance(this).enqueue(updateWork);

        WorkManager.getInstance(this).getWorkInfoByIdLiveData(updateWork.getId()).observe(this, workInfo -> {
            if (workInfo != null) {
                if (workInfo.getState() == WorkInfo.State.SUCCEEDED) {
                    tvUpdateStatus.setText(R.string.update_success);
                    btnCheckUpdates.setEnabled(true);
                } else if (workInfo.getState() == WorkInfo.State.FAILED) {
                    tvUpdateStatus.setText(R.string.update_failed);
                    btnCheckUpdates.setEnabled(true);
                }
            }
        });
    }
}
