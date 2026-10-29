-- =========================================================================
-- BettingShield — Cloud PostgreSQL / Supabase Database Schema
-- Run this in your Supabase SQL Editor (https://supabase.com -> SQL Editor)
-- Provides 24/7 cloud persistence for domains, package signatures & versions
-- =========================================================================

-- 1. Enable UUID Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Blocked Domains Table
CREATE TABLE IF NOT EXISTS public.blocked_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain TEXT UNIQUE NOT NULL,
    category TEXT DEFAULT 'wagering',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for high-performance domain matching
CREATE INDEX IF NOT EXISTS idx_blocked_domains_domain ON public.blocked_domains(domain);

-- 3. Blocked App Packages Table
CREATE TABLE IF NOT EXISTS public.blocked_packages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_name TEXT UNIQUE NOT NULL,
    app_name TEXT NOT NULL,
    category TEXT DEFAULT 'sports_betting',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Blocklist Metadata & Anti-Rollback Versions Table
CREATE TABLE IF NOT EXISTS public.blocklist_meta (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version INT NOT NULL,
    rules_hash TEXT,
    signature TEXT,
    published_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Seed Verified Domains (Including playveer.com and major bookmakers)
INSERT INTO public.blocked_domains (domain, category) VALUES
    ('playveer.com', 'wagering'),
    ('bet365.com', 'sportsbook'),
    ('betway.com', 'sportsbook'),
    ('1xbet.com', 'sportsbook'),
    ('parimatch.com', 'sportsbook'),
    ('parimatch.in', 'sportsbook'),
    ('stake.com', 'casino_wagering'),
    ('pokerstars.com', 'poker'),
    ('unibet.com', 'sportsbook'),
    ('bwin.com', 'sportsbook'),
    ('williamhill.com', 'bookmaker'),
    ('ladbrokes.com', 'bookmaker'),
    ('dafabet.com', 'sportsbook'),
    ('skybet.com', 'sportsbook'),
    ('paddypower.com', 'sportsbook'),
    ('betfair.com', 'betting_exchange'),
    ('draftkings.com', 'fantasy_sports'),
    ('fanduel.com', 'sportsbook'),
    ('betmgm.com', 'sportsbook'),
    ('pointsbet.com', 'sportsbook'),
    ('caesars.com', 'casino_sports'),
    ('888sport.com', 'sportsbook'),
    ('888casino.com', 'casino'),
    ('betsson.com', 'sportsbook'),
    ('leovegas.com', 'casino'),
    ('coral.co.uk', 'bookmaker'),
    ('betvictor.com', 'bookmaker'),
    ('sportingbet.com', 'sportsbook'),
    ('mpl.live', 'real_money_gaming'),
    ('dream11.com', 'fantasy_wagering'),
    ('my11circle.com', 'fantasy_wagering'),
    ('winzo.games', 'real_money_gaming'),
    ('rummypassion.com', 'real_money_gaming'),
    ('junglee.com', 'real_money_gaming'),
    ('betano.com', 'sportsbook'),
    ('betclic.com', 'sportsbook'),
    ('pinnacle.com', 'sportsbook'),
    ('betonline.ag', 'sportsbook'),
    ('bovada.lv', 'sportsbook'),
    ('sportsbet.com.au', 'sportsbook')
ON CONFLICT (domain) DO NOTHING;

-- 6. Seed Monitored Packages
INSERT INTO public.blocked_packages (package_name, app_name, category) VALUES
    ('com.bet365', 'Bet365', 'sports_betting'),
    ('com.betway.sports', 'Betway', 'sportsbook'),
    ('com.parimatch', 'Parimatch', 'sportsbook'),
    ('com.onebreak.stake', 'Stake', 'casino_wagering'),
    ('com.pokerstars', 'PokerStars', 'poker'),
    ('com.unibet', 'Unibet', 'sportsbook'),
    ('com.bwin', 'Bwin', 'sportsbook'),
    ('com.williamhill', 'William Hill', 'bookmaker'),
    ('com.ladbrokes', 'Ladbrokes', 'bookmaker'),
    ('com.dafabet', 'Dafabet', 'sportsbook'),
    ('com.draftkings.dknative', 'DraftKings', 'fantasy_sports'),
    ('com.fanduel.sportsbook', 'FanDuel', 'sportsbook'),
    ('com.dream11.android', 'Dream11', 'fantasy_wagering'),
    ('com.mpl.androidapp', 'MPL', 'real_money_gaming'),
    ('com.winzo.gold', 'WinZO', 'real_money_gaming')
ON CONFLICT (package_name) DO NOTHING;

-- 7. Seed Initial Version
INSERT INTO public.blocklist_meta (version, rules_hash)
VALUES (1, 'INITIAL_SEED_OFFLINE')
ON CONFLICT DO NOTHING;

-- 8. Row Level Security (RLS) - Secure public read, Admin-only write
ALTER TABLE public.blocked_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blocked_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blocklist_meta ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read access to active blocked domains"
    ON public.blocked_domains FOR SELECT USING (is_active = true);

CREATE POLICY "Allow public read access to active packages"
    ON public.blocked_packages FOR SELECT USING (is_active = true);

CREATE POLICY "Allow public read access to version metadata"
    ON public.blocklist_meta FOR SELECT USING (true);
