package com.bettingshield.app.data;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Built-in lookup catalog for popular wagering, gaming, streaming, and entertainment applications.
 * Enables users and administrators to block apps simply by App Name (e.g. "Sony LIV", "Bet365", "Dream11")
 * without needing to know Android's internal reverse-domain package names.
 */
public class AppCatalog {

    private static final Map<String, AppInfo> CATALOG = new HashMap<>();

    public static class AppInfo {
        public final String appName;
        public final String packageName;
        public final String category;

        public AppInfo(String appName, String packageName, String category) {
            this.appName = appName;
            this.packageName = packageName;
            this.category = category;
        }
    }

    static {
        // --- Wagering / Betting / Gambling / Fantasy ---
        register("Bet365", "com.bet365Wrapper.Bet365_Application", "Wagering");
        register("Stake", "com.stake.app", "Wagering");
        register("1xBet", "org.xbet.client", "Wagering");
        register("Parimatch", "com.parimatch.app", "Wagering");
        register("Dream11", "com.dream11.app", "Fantasy / Wagering");
        register("MPL", "com.mpl.androidapp", "Real Money Gaming");
        register("Mobile Premier League", "com.mpl.androidapp", "Real Money Gaming");
        register("My11Circle", "com.games24x7.my11circle", "Fantasy / Wagering");
        register("RummyCircle", "com.games24x7.rummycircle.rummy", "Wagering / Card Game");
        register("Junglee Rummy", "com.jungleerummy.play", "Wagering / Card Game");
        register("PokerBaazi", "com.pokerbaazi", "Wagering / Poker");
        register("WinZO", "com.winzo.gold", "Real Money Gaming");
        register("WinZO Games", "com.winzo.gold", "Real Money Gaming");
        register("Zupee", "com.zupee.app", "Real Money Gaming");
        register("A23", "com.hdworks.a23", "Wagering / Rummy");
        register("A23 Rummy", "com.hdworks.a23", "Wagering / Rummy");
        register("Gamezy", "com.gamezy", "Fantasy / Wagering");
        register("Howzat", "com.howzat.fantasy", "Fantasy / Wagering");
        register("FanCode", "com.fancode", "Sports / Wagering Info");
        register("22Bet", "com.bet22", "Wagering");
        register("Melbet", "org.melbet.client", "Wagering");
        register("Dafabet", "com.dafabet.mobile", "Wagering");
        register("10Cric", "com.ten.cric", "Wagering");
        register("Mostbet", "com.mostbet.client", "Wagering");
        register("Playveer", "com.playveer.app", "Wagering");
        register("PlayVeer", "com.playveer.app", "Wagering");
        register("4rabet", "com.four.rabet", "Wagering");
        register("Batery", "com.batery.bet", "Wagering");
        register("Betway", "com.betway.sports", "Wagering");
        register("Unibet", "com.unibet.sports", "Wagering");
        register("DraftKings", "com.draftkings.dknative", "Fantasy / Wagering");
        register("FanDuel", "com.fanduel.android.sportsbook", "Fantasy / Wagering");

        // --- Entertainment & Video Streaming (ex: Sony LIV requested by user) ---
        register("Sony LIV", "com.sonyliv", "Streaming / Entertainment");
        register("SonyLIV", "com.sonyliv", "Streaming / Entertainment");
        register("Disney+ Hotstar", "in.startv.hotstar", "Streaming / Entertainment");
        register("Hotstar", "in.startv.hotstar", "Streaming / Entertainment");
        register("JioCinema", "com.jio.media.ondemand", "Streaming / Entertainment");
        register("Netflix", "com.netflix.mediaclient", "Streaming / Entertainment");
        register("Amazon Prime Video", "com.amazon.avod.thirdpartyclient", "Streaming / Entertainment");
        register("Prime Video", "com.amazon.avod.thirdpartyclient", "Streaming / Entertainment");
        register("Zee5", "com.graymatrix.did", "Streaming / Entertainment");
        register("Aha", "aha.smart.ott", "Streaming / Entertainment");
        register("MX Player", "com.mxtech.videoplayer.ad", "Streaming / Entertainment");
        register("Voot", "com.tv.v18.viaphone", "Streaming / Entertainment");

        // --- Social & Browsers ---
        register("YouTube", "com.google.android.youtube", "Video");
        register("Instagram", "com.instagram.android", "Social");
        register("Facebook", "com.facebook.katana", "Social");
        register("Telegram", "org.telegram.messenger", "Messaging");
        register("Chrome", "com.android.chrome", "Browser");
    }

    private static void register(String name, String pkg, String category) {
        AppInfo info = new AppInfo(name, pkg, category);
        CATALOG.put(normalize(name), info);
    }

    private static String normalize(String s) {
        if (s == null) return "";
        return s.trim().toLowerCase().replaceAll("[^a-z0-9]", "");
    }

    /**
     * Resolves an app name to its known package info.
     * Supports exact normalized matching and prefix matching.
     */
    public static AppInfo findByName(String query) {
        if (query == null || query.trim().isEmpty()) return null;
        String norm = normalize(query);

        // 1. Direct match
        AppInfo exact = CATALOG.get(norm);
        if (exact != null) return exact;

        // 2. Contains match
        for (Map.Entry<String, AppInfo> entry : CATALOG.entrySet()) {
            if (entry.getKey().contains(norm) || norm.contains(entry.getKey())) {
                return entry.getValue();
            }
        }

        return null;
    }

    public static Map<String, AppInfo> getAll() {
        return Collections.unmodifiableMap(CATALOG);
    }
}
