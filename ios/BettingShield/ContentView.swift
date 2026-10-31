//
//  ContentView.swift
//  BettingShield iOS User Interface
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var engine: ShieldEngine
    @State private var showingAdminPinPrompt: Bool = false
    @State private var enteredPin: String = ""
    @State private var isPinValid: Bool = false
    @State private var showingAdminSheet: Bool = false
    @State private var pinError: String?

    var body: some View {
        NavigationView {
            ZStack {
                Color(red: 0.06, green: 0.09, blue: 0.16)
                    .ignoresSafeArea()

                VStack(spacing: 28) {
                    // Header Bar
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("BettingShield")
                                .font(.system(size: 24, weight: .bold))
                                .foregroundColor(.white)
                            Text("Privacy-First Prevention")
                                .font(.system(size: 13))
                                .foregroundColor(Color(red: 0.58, green: 0.65, blue: 0.73))
                        }
                        Spacer()
                        Button(action: {
                            enteredPin = ""
                            pinError = nil
                            showingAdminPinPrompt = true
                        }) {
                            Image(systemName: "lock.shield.fill")
                                .font(.system(size: 22))
                                .foregroundColor(Color(red: 0.01, green: 0.52, blue: 0.78))
                                .padding(10)
                                .background(Color(red: 0.12, green: 0.16, blue: 0.23))
                                .clipShape(Circle())
                        }
                    }
                    .padding(.horizontal)
                    .padding(.top, 10)

                    // Shield Status Card
                    VStack(spacing: 16) {
                        Image(systemName: engine.isProtectionActive ? "checkmark.shield.fill" : "shield.slash.fill")
                            .font(.system(size: 64))
                            .foregroundColor(engine.isProtectionActive ? Color(red: 0.11, green: 0.73, blue: 0.49) : Color(red: 0.94, green: 0.64, blue: 0.0))
                            .padding(.top, 12)

                        Text(engine.isProtectionActive ? "Protection is Active" : "Protection Paused")
                            .font(.system(size: 22, weight: .bold))
                            .foregroundColor(.white)

                        Text("Web requests and network traffic to wagering domains are blocked device-wide.")
                            .font(.system(size: 14))
                            .multilineTextAlignment(.center)
                            .foregroundColor(Color(red: 0.58, green: 0.65, blue: 0.73))
                            .padding(.horizontal, 20)

                        Button(action: {
                            engine.toggleProtection()
                        }) {
                            Text(engine.isProtectionActive ? "Pause Protection" : "Enable Protection")
                                .font(.system(size: 16, weight: .bold))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .frame(height: 50)
                                .background(engine.isProtectionActive ? Color(red: 0.12, green: 0.16, blue: 0.23) : Color(red: 0.01, green: 0.52, blue: 0.78))
                                .cornerRadius(12)
                        }
                        .padding(.horizontal, 20)
                        .padding(.bottom, 12)
                    }
                    .padding(16)
                    .background(Color(red: 0.12, green: 0.16, blue: 0.23))
                    .cornerRadius(20)
                    .overlay(
                        RoundedRectangle(cornerRadius: 20)
                            .stroke(Color(red: 0.2, green: 0.25, blue: 0.33), lineWidth: 1)
                    )
                    .padding(.horizontal)

                    // Privacy-Compliant Metrics (No rule names exposed)
                    HStack(spacing: 16) {
                        VStack(spacing: 6) {
                            Text("\(engine.blockedDomains.count)+")
                                .font(.system(size: 26, weight: .bold))
                                .foregroundColor(.white)
                            Text("Known Sites Guarded")
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 0.58, green: 0.65, blue: 0.73))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 18)
                        .background(Color(red: 0.12, green: 0.16, blue: 0.23))
                        .cornerRadius(14)

                        VStack(spacing: 6) {
                            Text("\(engine.blockedPackages.count)+")
                                .font(.system(size: 26, weight: .bold))
                                .foregroundColor(.white)
                            Text("Watched Apps")
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 0.58, green: 0.65, blue: 0.73))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 18)
                        .background(Color(red: 0.12, green: 0.16, blue: 0.23))
                        .cornerRadius(14)
                    }
                    .padding(.horizontal)

                    // Privacy Guarantee Banner
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: "lock.fill")
                                .foregroundColor(Color(red: 0.11, green: 0.73, blue: 0.49))
                            Text("100% Zero-Knowledge & Private")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.white)
                        }
                        Text("No browsing history is logged or sent to servers. Blocklists are enforced directly on your iPhone.")
                            .font(.system(size: 12))
                            .foregroundColor(Color(red: 0.58, green: 0.65, blue: 0.73))
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(red: 0.09, green: 0.13, blue: 0.19))
                    .cornerRadius(12)
                    .padding(.horizontal)

                    Spacer()
                }
            }
            .navigationBarHidden(true)
            .alert("Admin Authentication", isPresented: $showingAdminPinPrompt) {
                SecureField("Enter PIN (8888)", text: $enteredPin)
                Button("Unlock") {
                    if enteredPin == engine.masterPin {
                        showingAdminSheet = true
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Enter Master Admin PIN to view and modify blocked betting websites and applications.")
            }
            .sheet(isPresented: $showingAdminSheet) {
                AdminView()
                    .environmentObject(engine)
            }
        }
    }
}
