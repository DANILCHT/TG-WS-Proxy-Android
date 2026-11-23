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
    fun repeatedFreezesPutTlsBehindHttp() {
        CfModes.reportSuccess("a.example.com", tls = true)
        CfModes.reportSuccess("a.example.com", tls = true)
        val now = System.currentTimeMillis()
        assertTrue(CfModes.tlsFirst(now))
        assertFalse(CfModes.reportTlsFreeze(now))
        assertTrue(CfModes.reportTlsFreeze(now + 1_000))
        assertFalse(CfModes.tlsFirst(now + 2_000))
        assertTrue(CfModes.tlsPenalized(now + 2_000))
        // TLS is still tried, just second.
        assertEquals(listOf(false, true), CfModes.modesFor("a.example.com", allowTls = true, now = now + 2_000))
        assertFalse(CfModes.tlsPenalized(now + 1_000 + CfModes.FREEZE_PENALTY_MS + 1))
    }

    @Test
    fun freezesFarApartDoNotCount() {
        val now = 5_000_000L
        assertFalse(CfModes.reportTlsFreeze(now))
        assertFalse(CfModes.reportTlsFreeze(now + CfModes.FREEZE_WINDOW_MS + 1))
    }

    @Test
    fun frozenSessionShape() {
        assertTrue(CfModes.looksFrozen(downBytes = 16_000, upBytes = 3_000, durationMs = 20_000))
        assertFalse(CfModes.looksFrozen(downBytes = 0, upBytes = 3_000, durationMs = 20_000))
        assertFalse(CfModes.looksFrozen(downBytes = 500_000, upBytes = 3_000, durationMs = 20_000))
        assertFalse(CfModes.looksFrozen(downBytes = 16_000, upBytes = 3_000, durationMs = 600_000))
        assertFalse(CfModes.looksFrozen(downBytes = 16_000, upBytes = 0, durationMs = 20_000))
    }
}
