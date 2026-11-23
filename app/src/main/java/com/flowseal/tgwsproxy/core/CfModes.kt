package com.flowseal.tgwsproxy.core

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Remembers which transport reaches Cloudflare on the current network: TLS on
 * port 443 or plain HTTP (ws://) on port 80.
 *
 * Port of proxy/cf_websocket.py from upstream 1.12.0, adapted to the route
 * race. Since 16.11.2026 many Russian networks drop TLS to the CF proxy
 * domains while plain HTTP still passes; on other networks it is the other way
 * round, and a VPN on the phone changes the picture again. Nothing here is a
 * setting: both modes take part in the race and the network decides.
 *
 *  - a (domain, mode) pair that failed sits out [FAIL_COOLDOWN_MS], like
 *    upstream's `_cf_timeout_until`;
 *  - wins are counted per mode and the mode that wins more often is tried
 *    first (`cf_prefers_tls`). With no data plain HTTP goes first: that is what
 *    still works on most filtered networks;
 *  - TLS sessions that die right after their first ~16 KB (the throttling
 *    Russian ISPs apply to TLS towards Cloudflare) put TLS behind HTTP for
 *    [FREEZE_PENALTY_MS].
 *
 * Everything is forgotten on a network change, see [reset].
 */
object CfModes {

    /** Upstream CF_TIMEOUT_COOLDOWN. */
    const val FAIL_COOLDOWN_MS = 30_000L

    /** How long TLS stays behind plain HTTP once sessions over it freeze. */
    const val FREEZE_PENALTY_MS = 10 * 60_000L

    /** Frozen TLS sessions within [FREEZE_WINDOW_MS] that trigger the penalty. */
    const val FREEZE_REPORTS = 2
    const val FREEZE_WINDOW_MS = 3 * 60_000L

    private val cooldownUntil = ConcurrentHashMap<String, Long>()
    private val tlsWins = AtomicInteger()
    private val plainWins = AtomicInteger()
    private val freezes = ArrayDeque<Long>() // guarded by this

    @Volatile
    private var tlsPenaltyUntil = 0L

    @Synchronized
    fun reset() {
        cooldownUntil.clear()
        tlsWins.set(0)
        plainWins.set(0)
        freezes.clear()
        tlsPenaltyUntil = 0L
    }

    private fun key(host: String, tls: Boolean) = "${host.lowercase()}|${if (tls) "tls" else "http"}"

    /** True when TLS should be attempted before plain HTTP. */
    fun tlsFirst(now: Long = System.currentTimeMillis()): Boolean =
        now >= tlsPenaltyUntil && tlsWins.get() > plainWins.get()

    fun tlsPenalized(now: Long = System.currentTimeMillis()): Boolean = now < tlsPenaltyUntil

    fun inCooldown(host: String, tls: Boolean, now: Long = System.currentTimeMillis()): Boolean =
        (cooldownUntil[key(host, tls)] ?: 0L) > now

    /**
     * Modes to try for [host], best first (true = TLS, false = HTTP). Modes in
     * cooldown are left out; the caller decides what to do when nothing is left.
     */
    fun modesFor(
        host: String,
        allowTls: Boolean,
        allowPlain: Boolean = true,
        now: Long = System.currentTimeMillis(),
    ): List<Boolean> {
        val order = if (tlsFirst(now)) listOf(true, false) else listOf(false, true)
        return order.filter { (if (it) allowTls else allowPlain) && !inCooldown(host, it, now) }
    }

    /** Preferred mode among the allowed ones, ignoring cooldowns. */
    fun preferredMode(allowTls: Boolean, allowPlain: Boolean = true, now: Long = System.currentTimeMillis()): Boolean = when {
        !allowTls -> false
        !allowPlain -> true
        else -> tlsFirst(now)
    }

    fun reportFailure(host: String, tls: Boolean, now: Long = System.currentTimeMillis()) {
        if (cooldownUntil.size > 256) {
            cooldownUntil.entries.removeAll { it.value <= now }
        }
        cooldownUntil[key(host, tls)] = now + FAIL_COOLDOWN_MS
    }

    fun reportSuccess(host: String, tls: Boolean) {
        cooldownUntil.remove(key(host, tls))
        if (tls) tlsWins.incrementAndGet() else plainWins.incrementAndGet()
    }

    /**
     * A TLS session through Cloudflare carried a little data and then died.
     * Returns true when this report switched the penalty on.
     */
    @Synchronized
    fun reportTlsFreeze(now: Long = System.currentTimeMillis()): Boolean {
        while (freezes.isNotEmpty() && now - freezes.first() > FREEZE_WINDOW_MS) freezes.removeFirst()
        freezes.addLast(now)
        if (freezes.size < FREEZE_REPORTS || now < tlsPenaltyUntil) return false
        freezes.clear()
        tlsPenaltyUntil = now + FREEZE_PENALTY_MS
        tlsWins.set(0)
        return true
    }

    fun describe(now: Long = System.currentTimeMillis()): String {
        val first = if (tlsFirst(now)) "tls" else "http"
        val penalty = if (now < tlsPenaltyUntil) ", tls penalized ${(tlsPenaltyUntil - now) / 1000}s" else ""
        return "$first first (wins tls=${tlsWins.get()} http=${plainWins.get()}$penalty)"
    }

    /**
     * True for a TLS session that looks frozen by the ISP: some bytes came
     * down, far less than a working connection would carry, and it ended soon.
     * Pure so it can be unit-tested.
     */
    fun looksFrozen(downBytes: Long, upBytes: Long, durationMs: Long): Boolean =
        upBytes > 0 && downBytes in 1..FREEZE_MAX_DOWN_BYTES && durationMs in FREEZE_MIN_MS..FREEZE_MAX_MS

    /** The throttle lets ~16 KB through; leave room for TLS records and frames. */
    const val FREEZE_MAX_DOWN_BYTES = 24L * 1024
    const val FREEZE_MIN_MS = 3_000L
    const val FREEZE_MAX_MS = 90_000L
}
