# BettingShield - Privacy-First Wagering Prevention Android App

BettingShield is an Android application designed to help individuals curb exposure to online betting and gambling services quietly, discreetly, and without shame or surveillance.

---

## Key Highlights

- **100% Local & Private**: No web browsing history, DNS queries, or app usage logs are collected, stored, or sent to any server.
- **Dignified & Discreet**: No public alarms, no third-party reports to relatives or employers, and no stigmatizing language.
- **Offline-First**: Seeds known wagering websites and package signatures out-of-the-box upon first launch.
- **DNS Sinkholing via `VpnService`**: Intercepts DNS queries on port 53 locally and resolves gambling domains to `0.0.0.0` or `NXDOMAIN`, forwarding all legitimate traffic to upstream public DNS (`1.1.1.1` / `8.8.8.8`).
- **Cryptographically Signed Updates**: Rule updates are validated with RSA-2048 digital signatures and monotonic version checks to prevent tampering and downgrade attacks.
- **Mindful Pause Intervention**: Optional Usage Access detects when known betting apps open and offers an intentional pause screen with an instant escape to the home launcher.

---

## Project Structure

```
BettingShield/
├── app/
│   ├── build.gradle                          # App dependencies (Room, WorkManager, Material 3)
│   ├── src/
│   │   ├── main/
│   │   │   ├── AndroidManifest.xml           # Service & package query declarations
│   │   │   ├── java/com/bettingshield/app/
│   │   │   │   ├── BettingShieldApp.java     # Application initialization & auto-resume
│   │   │   │   ├── data/
│   │   │   │   │   ├── BlockedDomain.java    # Room entity for domain rules & allowlist
│   │   │   │   │   ├── BlockedPackage.java   # Room entity for known betting package IDs
│   │   │   │   │   ├── BlocklistMeta.java    # Room entity for blocklist version tracking
│   │   │   │   │   ├── ProtectionDao.java    # Room DAO interface with LiveData
│   │   │   │   │   └── ProtectionDatabase.java# Prepopulated offline SQLite database
│   │   │   │   ├── protection/
│   │   │   │   │   ├── BettingVpnService.java# Local DNS sinkhole TUN engine
│   │   │   │   │   ├── DomainFilter.java     # IDNA normalization & exact/subdomain matcher
│   │   │   │   │   ├── DnsPacketParser.java  # Pure Java IPv4/UDP/DNS wire protocol parser
│   │   │   │   │   ├── PackageDetector.java  # Package visibility & Device Owner evaluator
│   │   │   │   │   ├── AppLaunchMonitorService.java # Discreet foreground app watcher
│   │   │   │   │   ├── ShieldDeviceAdminReceiver.java # Device Admin for managed mode
│   │   │   │   │   └── ProtectionManager.java# Main coordinator singleton
│   │   │   │   ├── updates/
│   │   │   │   │   ├── BlocklistPayload.java # DTO for downloaded blocklist JSON
│   │   │   │   │   ├── SignatureVerifier.java# Cryptographic RSA-SHA256 signature verifier
│   │   │   │   │   └── RuleUpdateWorker.java # WorkManager periodic background updater
│   │   │   │   ├── privacy/
│   │   │   │   │   └── PrivacySettings.java  # Local shared preferences wrapper
│   │   │   │   └── ui/
│   │   │   │       ├── MainActivity.java     # Protection status dashboard
│   │   │   │       ├── WelcomeActivity.java  # Onboarding introduction
│   │   │   │       ├── ConsentActivity.java  # Transparent consent & principles
│   │   │   │       ├── SetupActivity.java    # VPN & Usage permission setup
│   │   │   │       ├── InterventionActivity.java # Mindful pause screen
│   │   │   │       ├── SettingsActivity.java # Custom exceptions & reset controls
│   │   │   │       └── BlockedDomainsAdapter.java # RecyclerView adapter
│   │   │   └── res/                          # Material 3 layouts, drawables, and themes
│   │   └── test/                             # Unit tests (DomainFilterTest)
├── ARCHITECTURE.md                           # In-depth technical architecture assessment
├── build.gradle                              # Root Gradle build script
├── settings.gradle                           # Gradle settings
└── README.md                                 # Documentation & test checklist
```

---

## Prerequisites & Building

- **IDE**: Android Studio Hedgehog (2023.1.1) or newer
- **JDK**: Java 11 or higher
- **Android SDK**:
  - `minSdkVersion`: 26 (Android 8.0 Oreo)
  - `targetSdkVersion`: 34 (Android 14) / 35
  - `compileSdkVersion`: 34

### Opening in Android Studio
1. Open Android Studio.
2. Select **Open an existing project**.
3. Navigate to `D:\SMR-Projects\BettingShield` and select the directory.
4. Allow Gradle to sync dependencies automatically.
5. Connect an Android device or emulator (API 26+) and click **Run 'app'**.

---

## Testing Plan & Verification Checklist

| Test Scenario | Verification Procedure | Proves Actual Blocking vs Detection |
| :--- | :--- | :--- |
| **1. VPN Authorization** | Launch app, complete Consent, tap "Authorize Filter" on Setup screen. Confirm Android VPN key icon appears in status bar. | System authorization test |
| **2. Known Betting Domain** | Open Chrome or mobile browser and navigate to `http://bet365.com` or `http://stake.com`. Confirm connection fails with `ERR_NAME_NOT_RESOLVED` or times out. | **Actual Blocking** |
| **3. Subdomain Blocking** | Navigate to `http://sports.bet365.com` or `http://api.stake.com`. Confirm query resolves to `0.0.0.0` or fails. | **Actual Blocking** |
| **4. False-Positive Prevention** | Navigate to `https://google.com`, `https://wikipedia.org`, or `https://notbet365.com`. Confirm pages load immediately without interference. | **Traffic Forwarding Integrity** |
| **5. Custom Allowlist Exception** | Go to Settings > Add `bet365.com` to exceptions. Verify `bet365.com` immediately loads. Remove from exceptions and verify it is blocked again. | **Dynamic Rule Reloading** |
| **6. Installed App Detection** | Open BettingShield. Confirm the "Identified Apps Watched" card reflects verified betting apps present on the device. | **Detection** |
| **7. Mindful Pause Intervention** | Grant Usage Access in Setup. Open a listed betting application. Confirm BettingShield triggers the gentle "Mindful Pause" screen. | **Detection & User Friction** |
| **8. Network Transition** | Toggle from Wi-Fi to Mobile Data (LTE/5G) while VPN is active. Verify browsing continues seamlessly and blocked domains remain blocked. | **Service Reliability** |
| **9. Device Reboot** | Restart device. Confirm BettingShield service safely recovers without crashing. | **Boot Reliability** |
| **10. Signature Verification** | In `RuleUpdateWorker`, verify that payloads with invalid signatures or older versions are rejected. | **Security & Anti-Rollback** |

---

## Compliance and Privacy Assurances

1. **No Data Collection**: BettingShield does not record visited URLs, DNS queries, or app usage sessions.
2. **Revocability**: Users can pause or stop protection at any moment with a single tap in the app dashboard or from the ongoing notification.
3. **No Coercion**: The app operates with user knowledge and consent; it does not masquerade as system software or deploy malicious root exploits.
