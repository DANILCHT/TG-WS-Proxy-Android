package com.flowseal.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class RouterTest {

    private fun routes(p: RoutePlanner.Input) = RoutePlanner.plan(p).map { it.route }

    private fun input(
        hasDirect: Boolean = true,
        frontingFirst: Boolean = false,
        relays: Int = 0,
        relayFirst: Boolean = false,
        cf: Int = 3,
        tcp: Boolean = true,
        preferred: Route? = null,
        demoted: Set<Route> = emptySet(),
    ) = RoutePlanner.Input(hasDirect, frontingFirst, relays, relayFirst, cf, tcp, preferred, demoted)

    // ---------------------------------------------------------------- planner

    @Test
    fun defaultOrderMatchesUpstreamLadder() {
        assertEquals(
            listOf(Route.DIRECT, Route.FRONTED, Route.RELAY, Route.CF, Route.CF, Route.CF, Route.TCP),
            routes(input(relays = 1)),
        )
    }

    @Test
    fun frontingFirstSwapsDirectPair() {
        assertEquals(Route.FRONTED, routes(input(frontingFirst = true)).first())
    }

    @Test
    fun relayFirstLeads() {
        val r = routes(input(relays = 2, relayFirst = true))
        assertEquals(listOf(Route.RELAY, Route.RELAY, Route.DIRECT), r.take(3))
    }

    @Test
    fun preferredRouteGoesFirstWithLongerHeadStart() {
        val plan = RoutePlanner.plan(input(relays = 1, preferred = Route.CF))
        assertEquals(Route.CF, plan[0].route)
        assertEquals(RoutePlanner.PREFERRED_HEAD_START_MS, plan[1].delayMs)
    }

    @Test
    fun demotedRoutesMoveToTheBackButStayBeforeTcp() {
        val r = routes(input(demoted = setOf(Route.DIRECT)))
        assertEquals(Route.FRONTED, r.first())
        assertEquals(Route.DIRECT, r[r.size - 2])
        assertEquals(Route.TCP, r.last())
    }

    @Test
    fun demotedPreferenceIsIgnored() {
        val r = routes(input(preferred = Route.DIRECT, demoted = setOf(Route.DIRECT)))
        assertEquals(Route.FRONTED, r.first())
    }

    @Test
    fun tcpIsLastWithExtraDelay() {
        val plan = RoutePlanner.plan(input(cf = 1))
        val tcp = plan.last()
        assertEquals(Route.TCP, tcp.route)
        assertTrue(tcp.delayMs - plan[plan.size - 2].delayMs >= RoutePlanner.TCP_EXTRA_DELAY_MS)
    }

    @Test
    fun delaysAreNonDecreasingAndIndexesCount() {
        val plan = RoutePlanner.plan(input(relays = 3))
        assertEquals(0L, plan[0].delayMs)
        for (i in 1 until plan.size) assertTrue(plan[i].delayMs >= plan[i - 1].delayMs)
        assertEquals(listOf(0, 1, 2), plan.filter { it.route == Route.RELAY }.map { it.index })
    }

    @Test
    fun onlyTcpStartsImmediately() {
        val plan = RoutePlanner.plan(input(hasDirect = false, cf = 0))
        assertEquals(1, plan.size)
        assertEquals(0L, plan[0].delayMs)
    }

    // ------------------------------------------------------------------ racer

    private val exec = Executors.newCachedThreadPool()

    private fun ok(route: Route, delay: Long, work: Long, closed: AtomicInteger? = null) =
        Attempt(route, route.tag, delay) {
            Thread.sleep(work)
            Upstream(route, route.tag, recycle = { closed?.incrementAndGet(); true })
        }

    private fun fail(route: Route, delay: Long, work: Long) =
        Attempt(route, route.tag, delay) {
            Thread.sleep(work)
            throw java.io.IOException("nope")
        }

    @Test
    fun fastestWins() {
        val up = Racer.race(
            listOf(ok(Route.DIRECT, 0, 600), ok(Route.CF, 100, 50)), exec, 5_000,
        )
        assertEquals(Route.CF, up!!.route)
    }

    @Test
    fun failurePullsNextAttemptForward() {
        val t0 = System.currentTimeMillis()
        val up = Racer.race(
            listOf(fail(Route.DIRECT, 0, 20), ok(Route.RELAY, 3_000, 10)), exec, 10_000,
        )
        assertEquals(Route.RELAY, up!!.route)
        assertTrue(System.currentTimeMillis() - t0 < 1_500)
    }

    @Test
    fun allFailingReturnsNull() {
        val failures = AtomicInteger()
        val up = Racer.race(
            listOf(fail(Route.DIRECT, 0, 10), fail(Route.CF, 50, 10)), exec, 5_000,
        ) { _, _ -> failures.incrementAndGet() }
        assertNull(up)
        assertEquals(2, failures.get())
    }

    @Test
    fun lateWinnersAreDiscarded() {
        val discarded = AtomicInteger()
        val latch = CountDownLatch(1)
        val slow = Attempt(Route.FRONTED, "slow", 0) {
            Thread.sleep(300)
            Upstream(Route.FRONTED, "slow", recycle = { discarded.incrementAndGet(); latch.countDown(); true })
        }
        val up = Racer.race(listOf(slow, ok(Route.DIRECT, 0, 10)), exec, 5_000)
        assertEquals(Route.DIRECT, up!!.route)
        assertTrue(latch.await(3, TimeUnit.SECONDS))
        assertEquals(1, discarded.get())
    }

    @Test
    fun deadlineStopsTheRace() {
        val t0 = System.currentTimeMillis()
        val up = Racer.race(listOf(ok(Route.DIRECT, 0, 2_000)), exec, 200)
        assertNull(up)
        assertTrue(System.currentTimeMillis() - t0 < 1_000)
    }
}
