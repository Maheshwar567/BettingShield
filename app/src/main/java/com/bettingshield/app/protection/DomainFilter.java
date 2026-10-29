package com.bettingshield.app.protection;

import java.net.IDN;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * High-performance domain matching engine with exact and subdomain matching,
 * IDNA / Punycode normalization, and false-positive prevention.
 *
 * Matching semantics:
 * - If "bet365.com" is blocked:
 *   - "bet365.com" -> BLOCKED
 *   - "www.bet365.com" -> BLOCKED
 *   - "sports.api.bet365.com" -> BLOCKED
 *   - "notbet365.com" -> ALLOWED (Prevents substring false positives)
 *   - "mybet365.com" -> ALLOWED
 *   - "bet365.com.evil.org" -> ALLOWED
 */
public class DomainFilter {

    private final Set<String> blockedDomains = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> allowedExceptions = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public DomainFilter() {}

    /**
     * Replaces the active blocked rules in memory.
     */
    public void setBlockedDomains(List<String> domains) {
        blockedDomains.clear();
        if (domains != null) {
            for (String domain : domains) {
                String normalized = normalizeHost(domain);
                if (!normalized.isEmpty()) {
                    blockedDomains.add(normalized);
                }
            }
        }
    }

    /**
     * Replaces the active allowed exceptions (whitelist) in memory.
     */
    public void setAllowedExceptions(List<String> exceptions) {
        allowedExceptions.clear();
        if (exceptions != null) {
            for (String exception : exceptions) {
                String normalized = normalizeHost(exception);
                if (!normalized.isEmpty()) {
                    allowedExceptions.add(normalized);
                }
            }
        }
    }

    /**
     * Tests whether a given hostname should be blocked.
     *
     * @param rawHostname Hostname extracted from DNS query or URL
     * @return true if hostname is in the blocked list and NOT overridden by an exception.
     */
    public boolean isBlocked(String rawHostname) {
        if (rawHostname == null || rawHostname.trim().isEmpty()) {
            return false;
        }

        String host = normalizeHost(rawHostname);
        if (host.isEmpty()) {
            return false;
        }

        // Check explicit user allowlist first (overrides any block)
        if (matchesRuleSet(host, allowedExceptions)) {
            return false;
        }

        // Check blocklist
        return matchesRuleSet(host, blockedDomains);
    }

    /**
     * Evaluates if a normalized host matches any rule in the given rule set.
     * Enforces strict subdomain boundary checking.
     */
    private boolean matchesRuleSet(String host, Set<String> rules) {
        if (rules.contains(host)) {
            return true;
        }

        // Walk up parent domain hierarchy:
        // For "sports.api.bet365.com", test "api.bet365.com", then "bet365.com"
        int dotIndex = host.indexOf('.');
        while (dotIndex != -1 && dotIndex < host.length() - 1) {
            String parent = host.substring(dotIndex + 1);
            if (rules.contains(parent)) {
                return true;
            }
            dotIndex = host.indexOf('.', dotIndex + 1);
        }

        return false;
    }

    /**
     * Normalizes a hostname:
     * 1. Strips leading/trailing whitespace.
     * 2. Removes trailing period (FQDN root dot).
     * 3. Converts to ASCII using Internationalizing Domain Names in Applications (IDNA / Punycode).
     * 4. Converts to lower case.
     */
    public static String normalizeHost(String hostname) {
        if (hostname == null) return "";
        String trimmed = hostname.trim();
        if (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        if (trimmed.isEmpty()) return "";

        try {
            // Converts Unicode international domains (e.g. Cyrillic/IDN homoglyphs) to ASCII punycode (e.g. xn--)
            return IDN.toASCII(trimmed, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.US);
        } catch (IllegalArgumentException e) {
            return trimmed.toLowerCase(Locale.US);
        }
    }

    public int getBlockedCount() {
        return blockedDomains.size();
    }

    public int getAllowedCount() {
        return allowedExceptions.size();
    }
}
