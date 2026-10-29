package com.bettingshield.app;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.bettingshield.app.protection.DomainFilter;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

public class DomainFilterTest {

    private DomainFilter domainFilter;

    @Before
    public void setUp() {
        domainFilter = new DomainFilter();
        domainFilter.setBlockedDomains(Arrays.asList(
                "bet365.com",
                "stake.com",
                "parimatch.in"
        ));
    }

    @Test
    public void testExactMatch() {
        assertTrue(domainFilter.isBlocked("bet365.com"));
        assertTrue(domainFilter.isBlocked("stake.com"));
        assertTrue(domainFilter.isBlocked("parimatch.in"));
    }

    @Test
    public void testSubdomainMatch() {
        assertTrue(domainFilter.isBlocked("www.bet365.com"));
        assertTrue(domainFilter.isBlocked("sports.api.bet365.com"));
        assertTrue(domainFilter.isBlocked("sub.stake.com"));
        assertTrue(domainFilter.isBlocked("live.parimatch.in"));
    }

    @Test
    public void testFalsePositivePrevention() {
        // Must NOT block domains containing the blocked string as substring
        assertFalse("notbet365.com should not be blocked", domainFilter.isBlocked("notbet365.com"));
        assertFalse("mybet365.com should not be blocked", domainFilter.isBlocked("mybet365.com"));
        assertFalse("bet365.com.news.org should not be blocked", domainFilter.isBlocked("bet365.com.news.org"));
        assertFalse("stakeholders.org should not be blocked", domainFilter.isBlocked("stakeholders.org"));
        assertFalse("google.com should not be blocked", domainFilter.isBlocked("google.com"));
    }

    @Test
    public void testNormalizationAndCaseInsensitivity() {
        assertTrue(domainFilter.isBlocked("BET365.COM"));
        assertTrue(domainFilter.isBlocked("  bet365.com.  ")); // Trailing dot & whitespace
        assertTrue(domainFilter.isBlocked("API.Stake.COM"));
    }

    @Test
    public void testAllowlistExceptionOverridesBlocklist() {
        assertTrue(domainFilter.isBlocked("bet365.com"));

        // Add explicit exception
        domainFilter.setAllowedExceptions(Collections.singletonList("bet365.com"));

        // Should now be permitted
        assertFalse(domainFilter.isBlocked("bet365.com"));
        assertFalse(domainFilter.isBlocked("sports.bet365.com"));

        // Other blocked domains should still be blocked
        assertTrue(domainFilter.isBlocked("stake.com"));
    }
}
