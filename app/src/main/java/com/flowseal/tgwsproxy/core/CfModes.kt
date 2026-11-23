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
 *  - sessions that the network freezes put their mode behind the other one
 *    for [FREEZE_PENALTY_MS]: TLS that dies after its first ~16 KB down (the
 *    throttling Russian ISPs apply to TLS towards Cloudflare), or any mode
 *    where tens of KB go up and not a single byte comes back.
 *
 * Everything is forgotten on a network change, see [reset].
 */
object CfModes {

    /** Upstream CF_TIMEOUT_COOLDOWN. */
    const val FAIL_COOLDOWN_MS = 30_000L

    /** How long a mode whose sessions freeze stays behind the other one. */
    const val FREEZE_PENALTY_MS = 10 * 60_000L

    /** Frozen sessions of one mode within [FREEZE_WINDOW_MS] that trigger the penalty. */
    const val FREEZE_REPORTS = 2
    const val FREEZE_WINDOW_MS = 3 * 60_000L

    private val cooldownUntil = ConcurrentHashMap<String, Long>()
    private val tlsWins = AtomicInteger()
    private val plainWins = AtomicInteger()
    private val freezes = HashMap<Boolean, ArrayDeque<Long>>() // guarded by this

    @Volatile
    private var tlsPenaltyUntil = 0L

    @Volatile
    private var plainPenaltyUntil = 0L

    @Synchronized
    fun reset() {
        cooldownUntil.clear()
        tlsWins.set(0)
        plainWins.set(0)
        freezes.clear()
        tlsPenaltyUntil = 0L
        plainPenaltyUntil = 0L
    }

    private fun key(host: String, tls: Boolean) = "${host.lowercase()}|${modeName(tls)}"

    fun modeName(tls: Boolean) = if (tls) "tls" else "http"

    fun penalized(tls: Boolean, now: Long = System.currentTimeMillis()): Boolean =
        now < (if (tls) tlsPenaltyUntil else plainPenaltyUntil)

    /** True when TLS should be attempted before plain HTTP. */
    fun tlsFirst(now: Long = System.currentTimeMillis()): Boolean {
        val tlsBad = penalized(true, now)
        val plainBad = penalized(false, now)
        if (tlsBad != plainBad) return plainBad
        return tlsWins.get() > plainWins.get()
    }

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
     * A session over [tls] was frozen by the network. Returns true when this
     * report switched the penalty for that mode on.
     */
    @Synchronized
    fun reportFreeze(tls: Boolean, now: Long = System.currentTimeMillis()): Boolean {
        val q = freezes.getOrPut(tls) { ArrayDeque() }
        while (q.isNotEmpty() && now - q.first() > FREEZE_WINDOW_MS) q.removeFirst()
        q.addLast(now)
        if (q.size < FREEZE_REPORTS || penalized(tls, now)) return false
        q.clear()
        if (tls) {
            tlsPenaltyUntil = now + FREEZE_PENALTY_MS
            tlsWins.set(0)
        } else {
            plainPenaltyUntil = now + FREEZE_PENALTY_MS
            plainWins.set(0)
        }
        return true
    }

    fun describe(now: Long = System.currentTimeMillis()): String {
        val first = modeName(tlsFirst(now))
        val penalties = listOf(true, false).filter { penalized(it, now) }.joinToString("") { tls ->
            val until = if (tls) tlsPenaltyUntil else plainPenaltyUntil
            ", ${modeName(tls)} penalized ${(until - now) / 1000}s"
        }
        return "$first first (wins tls=${tlsWins.get()} http=${plainWins.get()}$penalties)"
    }

    /**
     * True for a TLS session that looks throttled: some bytes came down, far
     * less than a working connection would carry, and it ended soon. Pure so
     * it can be unit-tested.
     */
    fun looksFrozen(downBytes: Long, upBytes: Long, durationMs: Long): Boolean =
        upBytes > 0 && downBytes in 1..FREEZE_MAX_DOWN_BYTES && durationMs in FREEZE_MIN_MS..FREEZE_MAX_MS

    /**
     * True for a session (any mode) where a real amount of data went up and
     * not one byte came back before it ended: the network swallowed the flow.
     * Telegram acknowledges every request, so a healthy session never looks
     * like this.
     */
    fun looksStalled(downBytes: Long, upBytes: Long, durationMs: Long): Boolean =
        downBytes == 0L && upBytes >= STALL_MIN_UP_BYTES && durationMs <= STALL_MAX_MS

    /** The throttle lets ~16 KB through; leave room for TLS records and frames. */
    const val FREEZE_MAX_DOWN_BYTES = 24L * 1024
    const val FREEZE_MIN_MS = 3_000L
    const val FREEZE_MAX_MS = 90_000L

    const val STALL_MIN_UP_BYTES = 16L * 1024
    const val STALL_MAX_MS = 60_000L
}
