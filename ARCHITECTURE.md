# Technical Architecture & Feasibility Assessment: BettingShield

## 1. Executive Summary & Feasibility Assessment

BettingShield is an Android application designed to discreetly protect individuals from accessing online wagering and gambling services. Operating in a privacy-first, consumer-focused environment requires strict adherence to Android's security sandbox, transparent consent models, and honest technical claims.

### Technical Distinction Matrix

| Capability | Mechanism | Consumer Android (Standard) | Managed Device (Device Owner) | Feasibility & Reliability |
| :--- | :--- | :--- | :--- | :--- |
| **Website Blocking** | Local DNS Sinkholing via `android.net.VpnService` | Supported with user consent | Supported | **100% Reliable** for standard DNS; requires Private DNS configuration for DoT/DoH. |
| **App Network Blocking** | Local DNS Sinkholing on app backend endpoints | Supported via VpnService | Supported | **High Reliability**; modern betting apps cannot render odds, authenticate, or submit bets without resolving API hostnames. |
| **App Detection (Static)** | `PackageManager` + `<queries>` | Supported via declared package visibility | Supported | **100% Reliable** for declared package identifiers. |
| **App Launch Detection (Dynamic)** | `UsageStatsManager` (`PACKAGE_USAGE_STATS`) | Supported with user-granted Special App Access | Supported | **High Reliability**; identifies foreground package transitions within 1–1.5 seconds. |
| **Atomic App Launch Prevention** | Process killing / Window suppression | **Not Supported** by consumer Android sandbox | Supported via `DevicePolicyManager.setPackagesSuspended()` | **Honest Assessment**: Consumer apps cannot atomically prevent third-party apps from launching without Device Owner privileges. |

---

## 2. Technical Evaluation of Android APIs

### A. Website & Network Blocking via `android.net.VpnService`
* **How it Works**: Android's `VpnService` allows the creation of a local virtual network (TUN) interface (`10.10.10.1/32`). All DNS requests directed to port 53 are captured locally.
* **Filter Engine (`DomainFilter`)**:
  - Exact and subdomain matching (e.g. blocking `bet365.com` will match `api.bet365.com`, but will **not** cause false positives on `notbet365.com` or `stakeholders.org`).
  - RFC 3492 Internationalizing Domain Names in Applications (IDNA / Punycode) normalization.
  - Returns `0.0.0.0` or `NXDOMAIN` for blocked domains.
  - Forwards permitted DNS requests to trusted upstream public resolvers (`1.1.1.1` and `8.8.8.8`) via raw DatagramSockets protected by `VpnService.protect(socket)`.
* **Privacy & Battery Efficiency**:
  - The VPN only intercepts DNS metadata (Port 53), not HTTP/HTTPS traffic payloads.
  - Zero web browsing history is stored or uploaded.
  - Minimal CPU/battery overhead compared to full MITM packet inspection.

### B. App Launch Detection vs. App Prevention
1. **The Sandbox Constraint**:
   On standard consumer Android, every application runs inside an isolated Linux UID sandbox. One application cannot kill another app's foreground process (`ActivityManager.killBackgroundProcesses` is deliberately restricted by Android to background processes only, which restart immediately).
2. **Accessibility Automation Flaws**:
   Parental control apps often abuse `AccessibilityService` to detect windows and simulate "Home" button presses. This is brittle, battery-draining, subject to timing race conditions, and actively penalized or rejected by Google Play Store policies.
3. **The Recommended Consumer Architecture**:
   * **Core Defense (Network Neutralization)**: Betting apps (e.g., Betway, Stake, 1xBet, Dream11) rely on WebViews, REST APIs, and WebSockets (`api.*`, `m.*`, `ws.*`). By sinkholing their API domains at the DNS level, the apps launch to permanent connection errors, rendering betting impossible.
   * **Mindful Pause Screen (`UsageStatsManager`)**: When a user opens a known betting app, BettingShield detects the `ACTIVITY_RESUMED` event and presents a gentle, non-stigmatizing intervention screen offering a pause and a quick exit to the home screen.
4. **Enterprise / Managed Mode (Device Owner)**:
   For users seeking hardware-level prevention, BettingShield includes `ShieldDeviceAdminReceiver`. If provisioned as Device Owner via ADB:
   ```bash
   adb shell dpm set-device-owner com.bettingshield.app/.protection.ShieldDeviceAdminReceiver
   ```
   BettingShield can invoke `DevicePolicyManager.setPackagesSuspended()`, completely disabling the apps on the launcher.

---

## 3. Cryptographic Rule Updates & Anti-Rollback Scheme

To safeguard against malicious blocklist tampering or downgrade attacks:
1. **JSON Payload**: Contains monotonic `version`, `timestamp`, `domains`, and `packages`.
2. **Signature Verification**: Verified against an embedded RSA-2048 / Ed25519 public key before any database modification.
3. **Rollback Guard**: Updates with `version <= currentVersion` are rejected automatically.
4. **Atomic Room Transactions**: Database updates execute within SQLite transactions, guaranteeing that invalid downloads never leave the database in an inconsistent state.

```
+--------------------------------------------------------+
|               Update Worker (WorkManager)              |
| 1. Download Signed JSON over HTTPS                     |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
|          SignatureVerifier (RSA-2048 / SHA-256)        |
| 2. Check Version > CurrentVersion (Anti-Rollback)      |
| 3. Verify Cryptographic Digital Signature              |
+--------------------------------------------------------+
                           | Valid
                           v
+--------------------------------------------------------+
|          ProtectionDatabase (Room / SQLite)            |
| 4. Atomic Transaction: Replace Rules & Update Meta     |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
|             DomainFilter (In-Memory Engine)            |
| 5. Instant Hot-Reload for Active VpnService            |
+--------------------------------------------------------+
```

---

## 4. Known Android Limitations & Mitigations

1. **Android Private DNS (DNS-over-TLS on Port 853)**:
   - *Limitation*: In Android 9+, if "Private DNS" is set to "Strict" (pointing to a custom DoT server), the OS bypasses the local VPN DNS server.
   - *Mitigation*: The app detects this state and prompts the user to set Private DNS to "Automatic" or "Off" in system settings.
2. **Single Active VPN Limitation**:
   - *Limitation*: Android only allows one active `VpnService` at a time. Activating another VPN will pause BettingShield.
   - *Mitigation*: The persistent status notification alerts the user if the VPN tunnel is closed.
