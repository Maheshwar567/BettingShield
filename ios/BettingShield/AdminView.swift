//
//  AdminView.swift
//  BettingShield iOS Master Admin Console
//

import SwiftUI

struct AdminView: View {
    @EnvironmentObject var engine: ShieldEngine
    @Environment(\.dismiss) var dismiss

    @State private var newDomain: String = ""
    @State private var newApp: String = ""
    @State private var selectedTab: Int = 0

    var body: some View {
        NavigationView {
            ZStack {
                Color(red: 0.06, green: 0.09, blue: 0.16)
                    .ignoresSafeArea()

                VStack(spacing: 16) {
                    // Segmented Selector
                    Picker("Category", selection: $selectedTab) {
                        Text("Websites (\(engine.blockedDomains.count))").tag(0)
                        Text("Apps (\(engine.blockedPackages.count))").tag(1)
                    }
                    .pickerStyle(SegmentedPickerStyle())
                    .padding(.horizontal)
                    .padding(.top, 10)

                    if selectedTab == 0 {
                        // Section: Blocked Websites
                        VStack(spacing: 12) {
                            HStack {
                                TextField("e.g. playveer.com", text: $newDomain)
                                    .padding(12)
                                    .background(Color(red: 0.12, green: 0.16, blue: 0.23))
                                    .cornerRadius(10)
                                    .foregroundColor(.white)
                                    .autocapitalization(.none)
                                    .disableAutocorrection(true)

                                Button(action: {
                                    engine.addBlockedDomain(newDomain)
                                    newDomain = ""
                                }) {
                                    Text("Block")
                                        .font(.system(size: 15, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 18)
                                        .padding(.vertical, 12)
                                        .background(Color(red: 0.01, green: 0.52, blue: 0.78))
                                        .cornerRadius(10)
                                }
                            }
                            .padding(.horizontal)

                            List {
                                ForEach(engine.blockedDomains, id: \.self) { domain in
                                    HStack {
                                        Image(systemName: "globe")
                                            .foregroundColor(Color(red: 0.01, green: 0.52, blue: 0.78))
                                        Text(domain)
                                            .foregroundColor(.white)
                                            .font(.system(size: 15))
                                        Spacer()
                                        Button(action: {
                                            engine.removeBlockedDomain(domain)
                                        }) {
                                            Image(systemName: "trash")
                                                .foregroundColor(Color(red: 0.94, green: 0.33, blue: 0.31))
                                        }
                                    }
                                    .listRowBackground(Color(red: 0.12, green: 0.16, blue: 0.23))
                                }
                            }
                            .listStyle(PlainListStyle())
                        }
                    } else {
                        // Section: Blocked Apps
                        VStack(spacing: 12) {
                            HStack {
                                TextField("App Name (e.g. Stake)", text: $newApp)
                                    .padding(12)
                                    .background(Color(red: 0.12, green: 0.16, blue: 0.23))
                                    .cornerRadius(10)
                                    .foregroundColor(.white)
                                    .autocapitalization(.none)

                                Button(action: {
                                    engine.addBlockedPackage(newApp)
                                    newApp = ""
                                }) {
                                    Text("Add")
                                        .font(.system(size: 15, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 18)
                                        .padding(.vertical, 12)
                                        .background(Color(red: 0.01, green: 0.52, blue: 0.78))
                                        .cornerRadius(10)
                                }
                            }
                            .padding(.horizontal)

                            List {
                                ForEach(engine.blockedPackages, id: \.self) { pkg in
                                    HStack {
                                        Image(systemName: "app.fill")
                                            .foregroundColor(Color(red: 0.11, green: 0.73, blue: 0.49))
                                        Text(pkg)
                                            .foregroundColor(.white)
                                            .font(.system(size: 15))
                                        Spacer()
                                        Button(action: {
                                            engine.removeBlockedPackage(pkg)
                                        }) {
                                            Image(systemName: "trash")
                                                .foregroundColor(Color(red: 0.94, green: 0.33, blue: 0.31))
                                        }
                                    }
                                    .listRowBackground(Color(red: 0.12, green: 0.16, blue: 0.23))
                                }
                            }
                            .listStyle(PlainListStyle())
                        }
                    }

                    // Cloud Sync & Bottom Actions
                    VStack(spacing: 10) {
                        Button(action: {
                            engine.syncRulesFromHub()
                        }) {
                            HStack {
                                Image(systemName: "arrow.triangle.2.circlepath")
                                Text(engine.isSyncing ? "Syncing..." : "Sync Rules with Hub / Cloud")
                            }
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 46)
                            .background(Color(red: 0.15, green: 0.22, blue: 0.32))
                            .cornerRadius(10)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom, 12)
                }
            }
            .navigationTitle("Admin Console")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                    .foregroundColor(.white)
                }
            }
        }
    }
}
