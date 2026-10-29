package com.bettingshield.app.ui;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.bettingshield.app.R;
import com.google.android.material.button.MaterialButton;

/**
 * Welcomes the user with discreet, non-stigmatizing framing.
 */
public class WelcomeActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_welcome);

        MaterialButton btnGetStarted = findViewById(R.id.btnGetStarted);
        btnGetStarted.setOnClickListener(v -> {
            Intent intent = new Intent(WelcomeActivity.this, ConsentActivity.class);
            startActivity(intent);
            finish();
        });
    }
}
