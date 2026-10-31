# BettingShield for iOS (iPhone & iPad)

This folder contains the native iOS implementation and guidelines for installing the BettingShield App on iPhone and iPad devices.

---

## Method 1: Instant App Installation on iPhone (Zero Mac / Zero Xcode Required)

Apple iOS supports Progressive Web Apps (PWA) which install directly onto the iPhone Home Screen as a native app icon with standalone window mode (no Safari address bar):

1. On your iPhone, open **Safari** and navigate to your BettingShield server:
   ```text
   http://192.168.31.186:8085
   ```
2. Tap the **Share** button at the bottom (square with arrow up ⬆️).
3. Scroll down and tap **Add to Home Screen (➕)**.
4. Tap **Add** in the top-right corner.
5. **BettingShield is now installed as an App on your iPhone home screen!**
6. Tap the **BettingShield** icon to open it in full-screen app mode.
7. Tap the **Lock Icon** in the top right and enter PIN `8888` to manage blocked websites and apps directly from your iPhone!
8. Tap **Activate iOS Protection Profile** to enforce device-wide network blocking.

---

## Method 2: Native Swift Project (Xcode / TestFlight / Sideloadly)

For users with a Mac or Apple Developer account:
- Source code files in `BettingShield/`:
  - `BettingShieldApp.swift`: SwiftUI App entrypoint.
  - `ContentView.swift`: Privacy-first player interface.
  - `AdminView.swift`: In-App Admin management console.
  - `ShieldEngine.swift`: NEDNSSettingsManager & hub synchronization.
- Open the directory in Xcode, select your team signing, and deploy directly to your iPhone.
