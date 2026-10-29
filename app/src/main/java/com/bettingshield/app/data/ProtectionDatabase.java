package com.bettingshield.app.data;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;
import androidx.sqlite.db.SupportSQLiteDatabase;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main Room Database providing persistent, offline-first storage for
 * blocked domains, package identifiers, and update metadata.
 */
@Database(entities = {BlockedDomain.class, BlockedPackage.class, BlocklistMeta.class}, version = 1, exportSchema = false)
public abstract class ProtectionDatabase extends RoomDatabase {

    private static volatile ProtectionDatabase INSTANCE;
    public abstract ProtectionDao protectionDao();

    public static final ExecutorService databaseWriteExecutor =
            Executors.newFixedThreadPool(4);

    public static ProtectionDatabase getDatabase(final Context context) {
        if (INSTANCE == null) {
            synchronized (ProtectionDatabase.class) {
                if (INSTANCE == null) {
                    INSTANCE = Room.databaseBuilder(
                            context.getApplicationContext(),
                            ProtectionDatabase.class,
                            "bettingshield_database"
                    )
                    .addCallback(sRoomDatabaseCallback)
                    .fallbackToDestructiveMigration()
                    .build();
                }
            }
        }
        return INSTANCE;
    }

    private static final RoomDatabase.Callback sRoomDatabaseCallback = new RoomDatabase.Callback() {
        @Override
        public void onCreate(@NonNull SupportSQLiteDatabase db) {
            super.onCreate(db);
            databaseWriteExecutor.execute(() -> {
                if (INSTANCE == null) return;
                ProtectionDao dao = INSTANCE.protectionDao();

                // Seed Default Verified Domains (Offline-First)
                long now = System.currentTimeMillis();
                List<BlockedDomain> defaultDomains = new ArrayList<>();
                String[] domains = {
                    "playveer.com", "playverr.com", "bet365.com", "betway.com", "1xbet.com", "parimatch.com", "parimatch.in",
                    "stake.com", "pokerstars.com", "unibet.com", "bwin.com", "williamhill.com",
                    "ladbrokes.com", "dafabet.com", "skybet.com", "paddypower.com", "betfair.com",
                    "draftkings.com", "fanduel.com", "betmgm.com", "pointsbet.com", "caesars.com",
                    "888sport.com", "888casino.com", "betsson.com", "leovegas.com", "coral.co.uk",
                    "betvictor.com", "sportingbet.com", "mpl.live", "dream11.com", "my11circle.com",
                    "winzo.games", "rummypassion.com", "junglee.com", "betano.com", "betclic.com",
                    "pinnacle.com", "betonline.ag", "bovada.lv", "sportsbet.com.au"
                };

                for (String domain : domains) {
                    defaultDomains.add(new BlockedDomain(domain, "verified_wagering", false, now));
                }
                dao.insertDomains(defaultDomains);

                // Seed Default Verified Packages (Offline-First)
                List<BlockedPackage> defaultPackages = new ArrayList<>();
                defaultPackages.add(new BlockedPackage("com.bet365", "Bet365", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.betway.sports", "Betway", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.parimatch", "Parimatch", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.onebreak.stake", "Stake", "casino_crypto", now));
                defaultPackages.add(new BlockedPackage("com.pokerstars", "PokerStars", "poker", now));
                defaultPackages.add(new BlockedPackage("com.unibet", "Unibet", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.bwin", "Bwin", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.williamhill", "William Hill", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.ladbrokes", "Ladbrokes", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.dafabet", "Dafabet", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.skybet", "Sky Bet", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.paddypower", "Paddy Power", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.betfair", "Betfair", "sports_betting", now));
                defaultPackages.add(new BlockedPackage("com.draftkings.dknative", "DraftKings", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.fanduel.sportsbook", "FanDuel", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.betmgm", "BetMGM", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.pointsbet", "PointsBet", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.caesars.sportsbook", "Caesars Sportsbook", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.eighteighteight.sport", "888sport", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.betsson", "Betsson", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.leovegas", "LeoVegas", "casino", now));
                defaultPackages.add(new BlockedPackage("com.coral", "Coral", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.betvictor", "BetVictor", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.sportingbet", "Sportingbet", "sportsbook", now));
                defaultPackages.add(new BlockedPackage("com.dream11.android", "Dream11", "fantasy_wagering", now));
                defaultPackages.add(new BlockedPackage("com.my11circle.android", "My11Circle", "fantasy_wagering", now));
                defaultPackages.add(new BlockedPackage("com.myteam11", "MyTeam11", "fantasy_wagering", now));
                defaultPackages.add(new BlockedPackage("com.mpl.androidapp", "MPL", "real_money_gaming", now));
                defaultPackages.add(new BlockedPackage("com.winzo.gold", "WinZO Gold", "real_money_gaming", now));
                defaultPackages.add(new BlockedPackage("com.junglee.rummy", "Junglee Rummy", "real_money_gaming", now));
                defaultPackages.add(new BlockedPackage("com.rummypassion.app", "Rummy Passion", "real_money_gaming", now));

                dao.insertPackages(defaultPackages);

                // Initial Blocklist Metadata
                dao.insertMeta(new BlocklistMeta("active_rules", 1, now, "INITIAL_OFFLINE_VERIFIED_SEED"));
            });
        }
    };
}
