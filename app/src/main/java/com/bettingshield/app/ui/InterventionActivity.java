package com.bettingshield.app.ui;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.bettingshield.app.R;
import com.google.android.material.button.MaterialButton;

/**
 * Discreet, supportive screen displayed when an identified betting application is opened.
 * Provides intentional friction to help user step back.
 */
public class InterventionActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_intervention);

        MaterialButton btnHome = findViewById(R.id.btnHome);
        MaterialButton btnDismiss = findViewById(R.id.btnDismiss);

        btnHome.setOnClickListener(v -> {
            // Send user safely back to launcher home screen
            Intent homeIntent = new Intent(Intent.ACTION_MAIN);
            homeIntent.addCategory(Intent.CATEGORY_HOME);
            homeIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(homeIntent);
            finish();
        });

        btnDismiss.setOnClickListener(v -> finish());
    }

    @Override
    public void onBackPressed() {
        // Return to home on back press to maintain gentle protection
        Intent homeIntent = new Intent(Intent.ACTION_MAIN);
        homeIntent.addCategory(Intent.CATEGORY_HOME);
        homeIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(homeIntent);
        finish();
    }
}
