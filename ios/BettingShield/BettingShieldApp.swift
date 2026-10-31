//
//  BettingShieldApp.swift
//  BettingShield iOS Native Application
//

import SwiftUI

@main
struct BettingShieldApp: App {
    @StateObject private var shieldEngine = ShieldEngine()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(shieldEngine)
        }
    }
}
