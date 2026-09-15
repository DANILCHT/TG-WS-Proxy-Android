package com.flowseal.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Port of proxy/utils.py::DomainCensorFilter behaviour plus the mobile-data
 * profile overrides: user domains must not leak into logs, Telegram's own
 * domains stay readable.
 */
class LoggerCensorTest {

    @Test
    fun telegramDomainsPassThrough() {
        assertEquals(
            "wss://kws2.web.telegram.org/apiws via 149.154.167.220",
            Logger.censorDomains("wss://kws2.web.telegram.org/apiws via 149.154.167.220"),
        )
        assertEquals("telegram.org ok", Logger.censorDomains("telegram.org ok"))
    }

    @Test
    fun userDomainIsCensoredButTldKept() {
        val out = Logger.censorDomains("CF worker my-worker.example.com failed")
        assertTrue("expected censored host, got: $out", out.endsWith(".com failed"))
        assertFalse("raw host leaked: $out", "my-worker.example.com" in out)
        assertFalse("raw label leaked: $out", "my-worker" in out)
        assertFalse("raw label leaked: $out", "example" in out)
    }

    @Test
    fun censoringMatchesPythonRule() {
        // part[:len//2] + '*' * rest, TLD untouched.
        assertEquals("sprin*****.ru", Logger.censorDomains("sprinthost.ru"))
        assertEquals("ab**.cd**.ru", Logger.censorDomains("abcd.cdef.ru"))
    }

    @Test
    fun ipAddressesAndPortsUntouched() {
        val line = "DC2 WS connect to 149.154.167.220 was timed out"
        assertEquals(line, Logger.censorDomains(line))
    }

    @Test
    fun logSuffixUntouched() {
        assertEquals("saved debug.log", Logger.censorDomains("saved debug.log"))
    }

    @Test
    fun singleLabelWordsUntouched() {
        assertEquals("fallback closed", Logger.censorDomains("fallback closed"))
    }

    // ------------------------------------------------------- mobile profile

    @Test
    fun mobileProfileForcesEvasionOnCellular() {
        val cfg = ProxyConfig()
        cfg.fragmentClientHello = false
        cfg.frontingFirst = false
        assertTrue(cfg.applyMobileProfile(true))
        assertTrue(cfg.fragmentClientHello)
        assertTrue(cfg.frontingFirst)
    }

    @Test
    fun mobileProfileLeavesWifiAlone() {
        val cfg = ProxyConfig()
        cfg.fragmentClientHello = false
        cfg.frontingFirst = false
        assertFalse(cfg.applyMobileProfile(false))
        assertFalse(cfg.fragmentClientHello)
        assertFalse(cfg.frontingFirst)
    }

    @Test
    fun mobileProfileNoopWhenAlreadyOn() {
        val cfg = ProxyConfig()
        cfg.fragmentClientHello = true
        cfg.frontingFirst = true
        assertFalse(cfg.applyMobileProfile(true))
    }

    @Test
    fun mobileProfileRespectsOptOut() {
        val cfg = ProxyConfig()
        cfg.mobileEvasion = false
        cfg.fragmentClientHello = false
        assertFalse(cfg.applyMobileProfile(true))
        assertFalse(cfg.fragmentClientHello)
    }

    @Test
    fun mobileEvasionCopied() {
        val cfg = ProxyConfig()
        cfg.mobileEvasion = false
        assertFalse(cfg.copy().mobileEvasion)
    }

    // ------------------------------------------------- recommendation logic

    @Test
    fun recommendationPrefersDirect() {
        assertTrue(
            Diagnostics.buildRecommendation(true, true, false, false)
                .contains("no evasion", ignoreCase = true)
        )
    }

    @Test
    fun recommendationSuggestsFronting() {
        assertTrue(
            Diagnostics.buildRecommendation(true, false, true, false)
                .contains("fronting", ignoreCase = true)
        )
    }

    @Test
    fun recommendationSuggestsCf() {
        assertTrue(
            Diagnostics.buildRecommendation(true, false, false, true)
                .contains("CF", ignoreCase = true)
        )
    }

    @Test
    fun recommendationSuggestsSplitOnTlsOnlyFailure() {
        val tlsBlocked = Diagnostics.buildRecommendation(true, false, false, false)
        assertTrue("got: $tlsBlocked", tlsBlocked.contains("split", ignoreCase = true))
    }

    @Test
    fun recommendationOnTotalFailure() {
        assertTrue(
            Diagnostics.buildRecommendation(false, false, false, false)
                .contains("Nothing reachable")
        )
    }
}
