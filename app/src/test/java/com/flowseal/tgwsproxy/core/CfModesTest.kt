package com.flowseal.tgwsproxy.core

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CfModesTest {

    @Before
    fun setUp() = CfModes.reset()

    @After
    fun tearDown() = CfModes.reset()

    @Test
    fun plainHttpGoesFirstWithNoData() {
        assertEquals(listOf(false, true), CfModes.modesFor("a.example.com", allowTls = true))
    }

    @Test
    fun noSecureLeavesOnlyPlain() {
        assertEquals(listOf(false), CfModes.modesFor("a.example.com", allowTls = false))
        assertFalse(CfModes.preferredMode(allowTls = false))
    }

    @Test
    fun tlsLeadsOnceItWinsMore() {
        CfModes.reportSuccess("a.example.com", tls = true)
        assertEquals(listOf(true, false), CfModes.modesFor("b.example.com", allowTls = true))
        CfModes.reportSuccess("a.example.com", tls = false)
        CfModes.reportSuccess("a.example.com", tls = false)
        assertEquals(listOf(false, true), CfModes.modesFor("b.example.com", allowTls = true))
    }

    @Test
    fun failedPairSitsOutTheCooldownOnlyForThatDomainAndMode() {
        val now = 1_000_000L
        CfModes.reportFailure("a.example.com", tls = true, now = now)
        assertEquals(listOf(false), CfModes.modesFor("a.example.com", allowTls = true, now = now + 1))
        assertEquals(listOf(false, true), CfModes.modesFor("b.example.com", allowTls = true, now = now + 1))
        assertEquals(
            listOf(false, true),
            CfModes.modesFor("a.example.com", allowTls = true, now = now + CfModes.FAIL_COOLDOWN_MS + 1),
        )
    }

    @Test
    fun successClearsTheCooldown() {
        CfModes.reportFailure("a.example.com", tls = false)
        CfModes.reportSuccess("a.example.com", tls = false)
        assertTrue(CfModes.modesFor("a.example.com", allowTls = true).contains(false))
    }

    @Test
    fun repeatedTlsFreezesPutTlsBehindHttp() {
        CfModes.reportSuccess("a.example.com", tls = true)
        CfModes.reportSuccess("a.example.com", tls = true)
        val now = System.currentTimeMillis()
        assertTrue(CfModes.tlsFirst(now))
        assertFalse(CfModes.reportFreeze(tls = true, now = now))
        assertTrue(CfModes.reportFreeze(tls = true, now = now + 1_000))
        assertFalse(CfModes.tlsFirst(now + 2_000))
        assertTrue(CfModes.penalized(tls = true, now = now + 2_000))
        // TLS is still tried, just second.
        assertEquals(listOf(false, true), CfModes.modesFor("a.example.com", allowTls = true, now = now + 2_000))
        assertFalse(CfModes.penalized(tls = true, now = now + 1_000 + CfModes.FREEZE_PENALTY_MS + 1))
    }

    @Test
    fun repeatedHttpFreezesPutHttpBehindTls() {
        CfModes.reportSuccess("a.example.com", tls = false)
        val now = System.currentTimeMillis()
        assertFalse(CfModes.tlsFirst(now))
        CfModes.reportFreeze(tls = false, now = now)
        assertTrue(CfModes.reportFreeze(tls = false, now = now + 1_000))
        assertTrue(CfModes.tlsFirst(now + 2_000))
        assertEquals(listOf(true, false), CfModes.modesFor("a.example.com", allowTls = true, now = now + 2_000))
        // With TLS off there is nothing to switch to: HTTP stays.
        assertEquals(listOf(false), CfModes.modesFor("a.example.com", allowTls = false, now = now + 2_000))
    }

    @Test
    fun bothModesPenalizedFallsBackToWins() {
        val now = System.currentTimeMillis()
        CfModes.reportFreeze(tls = true, now = now)
        CfModes.reportFreeze(tls = true, now = now + 1)
        CfModes.reportFreeze(tls = false, now = now + 2)
        CfModes.reportFreeze(tls = false, now = now + 3)
        assertTrue(CfModes.penalized(tls = true, now = now + 10) && CfModes.penalized(tls = false, now = now + 10))
        assertFalse(CfModes.tlsFirst(now + 10))
    }

    @Test
    fun freezesFarApartDoNotCount() {
        val now = 5_000_000L
        assertFalse(CfModes.reportFreeze(tls = true, now = now))
        assertFalse(CfModes.reportFreeze(tls = true, now = now + CfModes.FREEZE_WINDOW_MS + 1))
    }

    @Test
    fun frozenTlsSessionShape() {
        assertTrue(CfModes.looksFrozen(downBytes = 16_000, upBytes = 3_000, durationMs = 20_000))
        assertFalse(CfModes.looksFrozen(downBytes = 0, upBytes = 3_000, durationMs = 20_000))
        assertFalse(CfModes.looksFrozen(downBytes = 500_000, upBytes = 3_000, durationMs = 20_000))
        assertFalse(CfModes.looksFrozen(downBytes = 16_000, upBytes = 3_000, durationMs = 600_000))
        assertFalse(CfModes.looksFrozen(downBytes = 16_000, upBytes = 0, durationMs = 20_000))
    }

    /** Numbers from a real 1.12.0 log on a home Wi-Fi (HTTP Host split on). */
    @Test
    fun stalledUploadShape() {
        // "^31.3KB (1 pkts) v0.0B (0 pkts) in 5.8s" and friends: frozen.
        assertTrue(CfModes.looksStalled(downBytes = 0, upBytes = 32_051, durationMs = 5_800))
        assertTrue(CfModes.looksStalled(downBytes = 0, upBytes = 31_948, durationMs = 1_200))
        assertTrue(CfModes.looksStalled(downBytes = 0, upBytes = 32_665, durationMs = 7_300))
        // Healthy sessions from the same log: small talk, and uploads that got acks.
        assertFalse(CfModes.looksStalled(downBytes = 839, upBytes = 1_536, durationMs = 5_900))
        assertFalse(CfModes.looksStalled(downBytes = 269, upBytes = 492, durationMs = 1_900))
        assertFalse(CfModes.looksStalled(downBytes = 4_198, upBytes = 5_033_165, durationMs = 15_500))
        // A long idle session that never got data is not a freeze of this kind.
        assertFalse(CfModes.looksStalled(downBytes = 0, upBytes = 32_000, durationMs = 300_000))
    }
}
