package com.bettingshield.app.ui;

import android.content.Intent;
import android.os.Bundle;
import android.widget.CheckBox;

import androidx.appcompat.app.AppCompatActivity;

import com.bettingshield.app.R;
import com.bettingshield.app.privacy.PrivacySettings;
import com.google.android.material.button.MaterialButton;

/**
 * Ensures explicit, transparent consent for local VPN and inspection.
 */
public class ConsentActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_consent);

        CheckBox cbConsent = findViewById(R.id.cbConsent);
        MaterialButton btnAgree = findViewById(R.id.btnAgree);

        cbConsent.setOnCheckedChangeListener((buttonView, isChecked) -> {
            btnAgree.setEnabled(isChecked);
        });

        btnAgree.setOnClickListener(v -> {
            PrivacySettings.getInstance(this).setConsentAgreed(true);
            Intent intent = new Intent(ConsentActivity.this, SetupActivity.class);
            startActivity(intent);
            finish();
        });
    }
}
