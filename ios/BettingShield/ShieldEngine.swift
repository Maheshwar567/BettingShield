//
//  ShieldEngine.swift
//  BettingShield iOS Core Engine
//

import Foundation
import NetworkExtension
import Combine

class ShieldEngine: ObservableObject {
    @Published var isProtectionActive: Bool = false
    @Published var blockedDomains: [String] = [
        "playveer.com", "playverr.com", "bet365.com", "betway.com", "1xbet.com",
        "parimatch.com", "parimatch.in", "stake.com", "pokerstars.com", "unibet.com",
        "bwin.com", "williamhill.com", "ladbrokes.com", "dafabet.com", "skybet.com",
        "paddypower.com", "betfair.com", "draftkings.com", "fanduel.com", "betmgm.com",
        "dream11.com", "mpl.live", "winzo.games"
    ]
    @Published var blockedPackages: [String] = [
        "Bet365", "Betway", "Stake", "Parimatch", "PokerStars", "Dream11", "MPL", "WinZO"
    ]
    @Published var isSyncing: Bool = false
    @Published var lastSyncDate: Date?

    private let hubUrl = "http://192.168.31.186:8085"
    let masterPin = "8888"

    init() {
        checkVpnStatus()
        syncRulesFromHub()
    }

    func toggleProtection() {
        if isProtectionActive {
            stopProtection()
        } else {
            startProtection()
        }
    }

    func startProtection() {
        // Enforce DNS settings via NEDNSSettingsManager
        NEDNSSettingsManager.shared().loadFromPreferences { [weak self] error in
            guard error == nil else { return }
            let manager = NEDNSSettingsManager.shared()
            let dohSettings = NEDNSOverHTTPSSettings(servers: ["1.1.1.1", "8.8.8.8"])
            dohSettings.serverURL = URL(string: "http://192.168.31.186:8085/dns-query")
            manager.dnsSettings = dohSettings
            manager.localizedDescription = "BettingShield Protection"
            manager.saveToPreferences { saveError in
                DispatchQueue.main.async {
                    self?.isProtectionActive = (saveError == nil)
                }
            }
        }
    }

    func stopProtection() {
        NEDNSSettingsManager.shared().removeFromPreferences { [weak self] _ in
            DispatchQueue.main.async {
                self?.isProtectionActive = false
            }
        }
    }

    private func checkVpnStatus() {
        NEDNSSettingsManager.shared().loadFromPreferences { [weak self] error in
            DispatchQueue.main.async {
                self?.isProtectionActive = (NEDNSSettingsManager.shared().isEnabled && error == nil)
            }
        }
    }

    func addBlockedDomain(_ domain: String) {
        let clean = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !clean.isEmpty, clean.contains(".") else { return }
        if !blockedDomains.contains(clean) {
            blockedDomains.insert(clean, at: 0)
            notifyHubAdd(domain: clean)
        }
    }

    func removeBlockedDomain(_ domain: String) {
        blockedDomains.removeAll { $0 == domain }
        notifyHubDelete(domain: domain)
    }

    func addBlockedPackage(_ name: String) {
        let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return }
        if !blockedPackages.contains(clean) {
            blockedPackages.insert(clean, at: 0)
        }
    }

    func removeBlockedPackage(_ name: String) {
        blockedPackages.removeAll { $0 == name }
    }

    func syncRulesFromHub() {
        guard let url = URL(string: "\(hubUrl)/api/rules") else { return }
        isSyncing = true
        URLSession.shared.dataTask(with: url) { [weak self] data, _, error in
            DispatchQueue.main.async {
                self?.isSyncing = false
                guard let data = data, error == nil else { return }
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let domains = json["domains"] as? [String] {
                    self?.blockedDomains = domains
                    self?.lastSyncDate = Date()
                }
            }
        }.resume()
    }

    private func notifyHubAdd(domain: String) {
        guard let url = URL(string: "\(hubUrl)/api/admin/add-domain") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer bettingshield-admin-token-secure-8888", forHTTPHeaderField: "Authorization")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["domain": domain])
        URLSession.shared.dataTask(with: req).resume()
    }

    private func notifyHubDelete(domain: String) {
        guard let url = URL(string: "\(hubUrl)/api/admin/delete-domain") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer bettingshield-admin-token-secure-8888", forHTTPHeaderField: "Authorization")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["domain": domain])
        URLSession.shared.dataTask(with: req).resume()
    }
}
