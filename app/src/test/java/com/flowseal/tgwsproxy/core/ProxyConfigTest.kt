package com.flowseal.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kotlin port of tests/test_config.py. */
class ProxyConfigTest {

    @Test
    fun parsesMultipleDcIpEntries() {
        assertEquals(
            mapOf(2 to "149.154.167.220", 4 to "1.2.3.4"),
            ProxyConfig.parseDcIpList(listOf("2:149.154.167.220", "4:1.2.3.4")),
        )
    }

    @Test
    fun lastEntryWinsForDuplicateDc() {
        assertEquals(
            mapOf(2 to "2.2.2.2"),
            ProxyConfig.parseDcIpList(listOf("2:1.1.1.1", "2:2.2.2.2")),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMissingSeparator() {
        ProxyConfig.parseDcIpList(listOf("2-1.2.3.4"))
    }

    @Test
    fun rejectsMalformedIpv4() {
        for (entry in listOf("2:149.154", "2:1.2.3.4.5", "2:999.1.1.1", "2:abc")) {
            var threw = false
            try {
                ProxyConfig.parseDcIpList(listOf(entry))
            } catch (e: IllegalArgumentException) {
                threw = true
            }
            assertTrue("expected rejection for $entry", threw)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsNonNumericDc() {
        ProxyConfig.parseDcIpList(listOf("x:1.2.3.4"))
    }

    @Test
    fun coerceSplitsOnCommonSeparators() {
        assertEquals(
            listOf("a.com", "b.com", "c.com", "d.com"),
            ProxyConfig.coerceDomainList("a.com, b.com; c.com d.com"),
        )
    }

    @Test
    fun coerceDeduplicatesCaseInsensitivelyKeepingFirst() {
        assertEquals(
            listOf("A.com"),
            ProxyConfig.coerceDomainList(listOf("A.com", "a.com")),
        )
    }

    @Test
    fun coerceFlattensSequencesAndSkipsNonStrings() {
        assertEquals(
            listOf("a.com", "b.com"),
            ProxyConfig.coerceDomainList(listOf("a.com b.com", 5, null)),
        )
    }

    @Test
    fun coerceReturnsEmptyForUnsupportedTypes() {
        assertEquals(emptyList<String>(), ProxyConfig.coerceDomainList(null))
        assertEquals(emptyList<String>(), ProxyConfig.coerceDomainList(42))
    }

    @Test
    fun acceptsOrdinaryDomains() {
        for (domain in listOf("example.com", "a-b.co.uk", "x.io")) {
            assertTrue(domain, ProxyConfig.isValidDomain(domain))
        }
    }

    @Test
    fun rejectsMalformedDomains() {
        val bad = listOf(
            "", "nodot", ".leading.com", "trailing.com.", "-bad.com", "bad-.com",
            "a..com", "a.1", "a." + "b".repeat(64), "a".repeat(250) + ".com",
        )
        for (domain in bad) {
            assertTrue(domain, !ProxyConfig.isValidDomain(domain))
        }
    }

    @Test
    fun normalizeLowercasesDedupesAndDropsInvalid() {
        assertEquals(
            listOf("b.com", "a.com"),
            ProxyConfig.normalizeDomainPool(listOf("B.com ", "b.com", "nodot", "a.com")),
        )
    }

    @Test
    fun decodedDefaultsMatchThePythonImplementation() {
        // Expected values produced by proxy/config.py::CFPROXY_DEFAULT_DOMAINS.
        val expected = listOf(
            "pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
            "lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk",
            "sorokodin.co.uk", "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk",
            "nebally.co.uk", "havegreatday.co.uk", "pomogite.co.uk", "fixtelega.co.uk",
            "sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk", "nothingthere.co.uk",
        )
        assertEquals(expected, ProxyConfig.CFPROXY_DEFAULT_DOMAINS)
    }

    @Test
    fun decodedDefaultsAreValidAndUnique() {
        assertTrue(ProxyConfig.CFPROXY_DEFAULT_DOMAINS.isNotEmpty())
        for (domain in ProxyConfig.CFPROXY_DEFAULT_DOMAINS) {
            assertTrue(domain, ProxyConfig.isValidDomain(domain))
        }
        assertEquals(
            ProxyConfig.CFPROXY_DEFAULT_DOMAINS.size,
            ProxyConfig.CFPROXY_DEFAULT_DOMAINS.toSet().size,
        )
    }

    @Test
    fun wsDomainsPreferenceMatchesPython() {
        // Upstream 1.12.0 dropped the kwsN-1 fallback for non-media.
        assertEquals(
            listOf("kws2.web.telegram.org"),
            Const.wsDomains(2, isMedia = false),
        )
        assertEquals(
            listOf("kws2-1.web.telegram.org", "kws2.web.telegram.org"),
            Const.wsDomains(2, isMedia = true),
        )
        // DC 203 is served by the DC2 endpoints.
        assertEquals(
            listOf("kws2.web.telegram.org"),
            Const.wsDomains(203, isMedia = false),
        )
    }

    @Test
    fun hexRoundTrip() {
        val bytes = Crypto.randomBytes(16)
        assertTrue(Const.fromHex(Const.toHex(bytes)).contentEquals(bytes))
    }
}
