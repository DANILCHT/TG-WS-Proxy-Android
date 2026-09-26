package com.flowseal.tgwsproxy.core

import java.util.concurrent.atomic.AtomicLong

/** Port of proxy/stats.py. Thread-safe counters. */
object Stats {

    val connectionsTotal = AtomicLong()
    val connectionsActive = AtomicLong()
    val connectionsWs = AtomicLong()
    val connectionsTcpFallback = AtomicLong()
    val connectionsCfproxy = AtomicLong()
    val connectionsRelay = AtomicLong()
    val connectionsFronting = AtomicLong()
    val connectionsBad = AtomicLong()
    val connectionsMasked = AtomicLong()
    val wsErrors = AtomicLong()
    val bytesUp = AtomicLong()
    val bytesDown = AtomicLong()
    val poolHits = AtomicLong()
    val poolMisses = AtomicLong()
    val cfPoolHits = AtomicLong()
    val cfPoolMisses = AtomicLong()

    /** Smoothed time from handshake to an open upstream, ms (0 = no data yet). */
    @Volatile
    var connectMsAvg: Long = 0
        private set

    @Volatile
    var lastRoute: String = ""

    fun recordConnect(ms: Long, route: String) {
        lastRoute = route
        val prev = connectMsAvg
        connectMsAvg = if (prev == 0L) ms else (prev * 3 + ms) / 4
    }

    fun reset() {
        for (c in listOf(
            connectionsTotal, connectionsActive, connectionsWs, connectionsTcpFallback,
            connectionsCfproxy, connectionsRelay, connectionsFronting, connectionsBad, connectionsMasked,
            wsErrors, bytesUp, bytesDown, poolHits, poolMisses, cfPoolHits, cfPoolMisses,
        )) c.set(0)
        connectMsAvg = 0
        lastRoute = ""
    }

    fun summary(): String {
        val poolTotal = poolHits.get() + poolMisses.get()
        val poolS = if (poolTotal > 0) "${poolHits.get()}/$poolTotal" else "n/a"
        val cfTotal = cfPoolHits.get() + cfPoolMisses.get()
        val cfS = if (cfTotal > 0) "${cfPoolHits.get()}/$cfTotal" else "n/a"
        return "total=${connectionsTotal.get()} " +
            "active=${connectionsActive.get()} " +
            "ws=${connectionsWs.get()} " +
            "tcp_fb=${connectionsTcpFallback.get()} " +
            "cf=${connectionsCfproxy.get()} " +
            "relay=${connectionsRelay.get()} " +
            "front=${connectionsFronting.get()} " +
            "bad=${connectionsBad.get()} " +
            "masked=${connectionsMasked.get()} " +
            "err=${wsErrors.get()} " +
            "pool=$poolS " +
            (if (connectMsAvg > 0) "connect=${connectMsAvg}ms " else "") +
            "cf_pool=$cfS " +
            "up=${Const.humanBytes(bytesUp.get())} " +
            "down=${Const.humanBytes(bytesDown.get())}"
    }
}
