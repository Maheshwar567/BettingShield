package com.bettingshield.app.ui;

import android.os.Bundle;
import android.widget.ImageButton;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.bettingshield.app.R;
import com.bettingshield.app.data.BlockedDomain;
import com.bettingshield.app.data.ProtectionDao;
import com.bettingshield.app.data.ProtectionDatabase;
import com.bettingshield.app.protection.DomainFilter;
import com.bettingshield.app.protection.ProtectionManager;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

/**
 * Settings and Exceptions screen allowing users to add allowlist exceptions
 * and reset rules to default.
 */
public class SettingsActivity extends AppCompatActivity {

    private TextInputEditText etDomain;
    private MaterialButton btnAddException;
    private RecyclerView rvExceptions;
    private MaterialButton btnResetRules;
    private BlockedDomainsAdapter adapter;

    private static final String ADMIN_PIN = "8888";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Enforce Admin PIN Gate so players/users cannot tamper with rules
        promptAdminPin();
    }

    private void promptAdminPin() {
        android.widget.EditText pinInput = new android.widget.EditText(this);
        pinInput.setInputType(android.text.InputType.TYPE_CLASS_NUMBER | android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pinInput.setHint("Enter 4-digit Admin PIN");

        new AlertDialog.Builder(this)
                .setTitle("Admin Authentication")
                .setMessage("Only administrators are permitted to view or manage blocked wagering sites.")
                .setView(pinInput)
                .setCancelable(false)
                .setPositiveButton("Unlock", (dialog, which) -> {
                    String entered = pinInput.getText().toString().trim();
                    if (ADMIN_PIN.equals(entered)) {
                        initSettingsUi();
                    } else {
                        Toast.makeText(this, "Incorrect Admin PIN", Toast.LENGTH_SHORT).show();
                        finish();
                    }
                })
                .setNegativeButton("Cancel", (dialog, which) -> finish())
                .show();
    }

    private void initSettingsUi() {
        setContentView(R.layout.activity_settings);

        ImageButton btnBack = findViewById(R.id.btnBack);
        btnBack.setOnClickListener(v -> finish());

        etDomain = findViewById(R.id.etDomain);
        btnAddException = findViewById(R.id.btnAddException);
        rvExceptions = findViewById(R.id.rvExceptions);
        btnResetRules = findViewById(R.id.btnResetRules);

        setupRecyclerView();
        observeExceptions();

        btnAddException.setOnClickListener(v -> addDomainException());
        btnResetRules.setOnClickListener(v -> confirmResetRules());
    }

    private void setupRecyclerView() {
        adapter = new BlockedDomainsAdapter(domain -> {
            ProtectionDatabase.databaseWriteExecutor.execute(() -> {
                ProtectionDatabase.getDatabase(this).protectionDao().deleteDomain(domain);
                ProtectionManager.getInstance(this).reloadRulesFromDatabase();
            });
        });

        rvExceptions.setLayoutManager(new LinearLayoutManager(this));
        rvExceptions.setAdapter(adapter);
    }

    private void observeExceptions() {
        ProtectionDatabase.getDatabase(this)
                .protectionDao()
                .getAllAllowedExceptionsLiveData()
                .observe(this, exceptions -> {
                    adapter.setDomains(exceptions);
                });
    }

    private void addDomainException() {
        String input = etDomain.getText() != null ? etDomain.getText().toString().trim() : "";
        String normalized = DomainFilter.normalizeHost(input);

        if (normalized.isEmpty() || !normalized.contains(".")) {
            Toast.makeText(this, "Please enter a valid domain (e.g. news.com)", Toast.LENGTH_SHORT).show();
            return;
        }

        ProtectionDatabase.databaseWriteExecutor.execute(() -> {
            BlockedDomain exception = new BlockedDomain(
                    normalized,
                    "user_exception",
                    true, // isAllowed = true
                    System.currentTimeMillis()
            );
            ProtectionDatabase.getDatabase(this).protectionDao().insertDomain(exception);
            ProtectionManager.getInstance(this).reloadRulesFromDatabase();
        });

        etDomain.setText("");
        Toast.makeText(this, "Exception added: " + normalized, Toast.LENGTH_SHORT).show();
    }

    private void confirmResetRules() {
        new AlertDialog.Builder(this)
                .setTitle("Reset Rules")
                .setMessage("This will clear custom exceptions and restore default verified wagering protection rules.")
                .setPositiveButton("Reset", (dialog, which) -> resetRules())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void resetRules() {
        ProtectionDatabase.databaseWriteExecutor.execute(() -> {
            ProtectionDatabase db = ProtectionDatabase.getDatabase(this);
            ProtectionDao dao = db.protectionDao();

            // Clear allowed exceptions
            for (BlockedDomain bd : dao.getAllAllowedExceptions()) {
                dao.deleteDomain(bd);
            }

            ProtectionManager.getInstance(this).reloadRulesFromDatabase();
            runOnUiThread(() -> Toast.makeText(this, "Rules restored to default", Toast.LENGTH_SHORT).show());
        });
    }
}
