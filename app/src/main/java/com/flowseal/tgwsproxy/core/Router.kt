package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.DataStream
import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.SocketStream
import com.flowseal.tgwsproxy.net.Tls
import com.flowseal.tgwsproxy.net.WsHandshakeError
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

/** The ways an MTProto connection can reach Telegram. */
enum class Route(val tag: String) {
    POOL("pool"),
    DIRECT("ws"),
    FRONTED("front"),
    RELAY("relay"),
    CF("cf"),
    TCP("tcp"),
}

/** An open upstream connection, ready to receive the relay init. */
class Upstream(
    val route: Route,
    val detail: String,
    val ws: RawWebSocket? = null,
    val tcp: Socket? = null,
    val useSplitter: Boolean = false,
    val onWin: () -> Unit = {},
    /** Offers a losing connection to a pool; true if it was taken. */
    private val recycle: (() -> Boolean)? = null,
) {
    fun discard() {
        if (runCatching { recycle?.invoke() == true }.getOrDefault(false)) return
        close()
    }

    fun close() {
        ws?.abort()
        runCatching { tcp?.close() }
    }
}

class Attempt(
    val route: Route,
    val detail: String,
    /** Start offset from the beginning of the race, ms. */
    val delayMs: Long,
    val run: () -> Upstream,
)

/**
 * Happy-eyeballs for upstream routes.
 *
 * The Python version walks direct WS -> worker -> CF -> TCP one after another,
 * each with a 5–10 s timeout, so on a filtered network a single new Telegram
 * connection could take tens of seconds. Here the attempts are staggered: the
 * next one starts after a short delay or as soon as the previous one fails,
 * whichever comes first, and the first to open wins. Late winners are handed
 * back through [Upstream.discard] (pooled when possible).
 */
object Racer {

    fun race(
        attempts: List<Attempt>,
        executor: Executor,
        deadlineMs: Long,
        onFailure: (Attempt, Throwable) -> Unit = { _, _ -> },
    ): Upstream? {
        if (attempts.isEmpty()) return null
        val results = LinkedBlockingQueue<Pair<Attempt, Result<Upstream>>>()
        val lock = Any()
        var done = false // guarded by lock
        val start = System.currentTimeMillis()
        var next = 0
        var running = 0

        fun launch() {
            val a = attempts[next++]
            running++
            try {
                executor.execute {
                    val r = try {
                        Result.success(a.run())
                    } catch (t: Throwable) {
                        Result.failure(t)
                    }
                    val orphan = synchronized(lock) {
                        if (done) true else {
                            results.put(a to r)
                            false
                        }
                    }
                    if (orphan) r.getOrNull()?.discard()
                }
            } catch (e: RejectedExecutionException) {
                running--
                onFailure(a, e)
            }
        }

        try {
            while (true) {
                val elapsed = System.currentTimeMillis() - start
                while (next < attempts.size && attempts[next].delayMs <= elapsed) launch()
                if (running == 0) {
                    if (next < attempts.size) {
                        launch()
                        continue
                    }
                    return null
                }
                if (elapsed >= deadlineMs) return null

                val nextDue = if (next < attempts.size) attempts[next].delayMs - elapsed else Long.MAX_VALUE
                val wait = minOf(nextDue, deadlineMs - elapsed).coerceAtLeast(1)
                val (attempt, result) = results.poll(wait, TimeUnit.MILLISECONDS) ?: continue
                running--
                val up = result.getOrNull()
                if (up != null) return up
                onFailure(attempt, result.exceptionOrNull() ?: IllegalStateException("no result"))
                // A failure pulls the next attempt forward instead of waiting out its delay.
                if (next < attempts.size) launch()
            }
        } finally {
            synchronized(lock) { done = true }
            while (true) {
                val (_, r) = results.poll() ?: break
                r.getOrNull()?.discard()
            }
        }
    }
}

/**
 * Pure ordering policy, separate from the I/O so it can be unit-tested.
 */
object RoutePlanner {

    class Input(
        val hasDirect: Boolean,
        val frontingFirst: Boolean,
        val relayCount: Int,
        val relayFirst: Boolean,
        val cfCount: Int,
        val hasTcp: Boolean,
        /** Route that worked last time for this DC (fresh entries only). */
        val preferred: Route? = null,
        /** Routes that recently failed or carried nothing; tried last. */
        val demoted: Set<Route> = emptySet(),
    )

    class Planned(val route: Route, val index: Int, val delayMs: Long)

    const val MAX_PER_ROUTE = 3

    /** Head start of the first attempt when nothing is known about the network. */
    const val HEAD_START_MS = 700L

    /** Head start of a route that is known to work on this network. */
    const val PREFERRED_HEAD_START_MS = 1_500L

    const val STEP_MS = 400L
    const val SAME_ROUTE_STEP_MS = 250L

    /** Plain TCP "connects" even where the DC is black-holed, so it goes last. */
    const val TCP_EXTRA_DELAY_MS = 2_500L

    fun plan(p: Input): List<Planned> {
        val direct = ArrayList<Route>()
        if (p.hasDirect) {
            if (p.frontingFirst) direct += listOf(Route.FRONTED, Route.DIRECT)
            else direct += listOf(Route.DIRECT, Route.FRONTED)
        }
        val relay = List(minOf(p.relayCount, MAX_PER_ROUTE)) { Route.RELAY }
        val cf = List(minOf(p.cfCount, MAX_PER_ROUTE)) { Route.CF }
        val tcp = if (p.hasTcp) listOf(Route.TCP) else emptyList()

        val groups = ArrayList<MutableList<Route>>()
        if (p.relayFirst) groups += listOf(relay.toMutableList(), direct, cf.toMutableList())
        else groups += listOf(direct, relay.toMutableList(), cf.toMutableList())

        val preferred = p.preferred?.let { if (it == Route.POOL) Route.DIRECT else it }
        if (preferred != null && preferred !in p.demoted) {
            val g = groups.firstOrNull { preferred in it }
            if (g != null) {
                groups.remove(g)
                g.remove(preferred)
                g.add(0, preferred)
                groups.add(0, g)
            }
        }

        // Demoted routes keep their relative order but move behind the rest.
        val flat = groups.flatten()
        val ordered = flat.filter { it !in p.demoted } + flat.filter { it in p.demoted }

        val out = ArrayList<Planned>()
        val seen = HashMap<Route, Int>()
        var t = 0L
        for ((i, r) in ordered.withIndex()) {
            if (i > 0) {
                val prev = ordered[i - 1]
                t += when {
                    i == 1 -> if (preferred != null && ordered[0] == preferred) PREFERRED_HEAD_START_MS else HEAD_START_MS
                    r == prev && (r == Route.RELAY || r == Route.CF) -> SAME_ROUTE_STEP_MS
                    else -> STEP_MS
                }
            }
            val idx = seen.getOrElse(r) { 0 }
            seen[r] = idx + 1
            out.add(Planned(r, idx, t))
        }
        if (tcp.isNotEmpty()) {
            val tcpDelay = if (out.isEmpty()) 0L else t + TCP_EXTRA_DELAY_MS
            out.add(Planned(Route.TCP, 0, tcpDelay))
        }
        return out
    }
}

/**
 * Picks and opens the upstream for one client connection, then relays it.
 * Owns the per-DC cooldowns that ProxyEngine used to keep, plus a memory of
 * which route worked, so the next connection goes there first.
 */
class Router(
    private val config: ProxyConfig,
    private val wsPool: WsPool,
    private val relayPool: RelayPool,
    private val executor: Executor,
) {

    companion object {
        private const val IP_FAIL_COOLDOWN_MS = 3_600_000L
        private const val DC_FAIL_COOLDOWN_MS = 60_000L
        private const val WS_BLACKLIST_COOLDOWN_MS = 600_000L
        private const val PREFERENCE_TTL_MS = 15 * 60_000L
        private const val DEMOTE_MS = 90_000L
        private const val RACE_DEADLINE_MS = 25_000L
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val HANDSHAKE_TIMEOUT_MS = 7_000

        /** A session this short that received nothing means the route is black-holed. */
        private const val DEAD_SESSION_MS = 15_000L
    }

    private class AllRedirects(val dc: Int) : Exception("all WS domains redirected")

    private val wsBlacklistUntil = ConcurrentHashMap<String, Long>()
    private val dcFailUntil = ConcurrentHashMap<String, Long>()
    private val ipFailUntil = ConcurrentHashMap<String, Long>()
    private val preferred = ConcurrentHashMap<String, Pair<Route, Long>>()
    private val demotedUntil = ConcurrentHashMap<String, Long>()

    /** Forget everything learned about the network (e.g. it just changed). */
    fun reset() {
        wsBlacklistUntil.clear()
        dcFailUntil.clear()
        ipFailUntil.clear()
        preferred.clear()
        demotedUntil.clear()
    }

    fun blacklistSummary(now: Long): String {
        val active = wsBlacklistUntil.entries.filter { it.value > now }.sortedBy { it.key }
        return if (active.isEmpty()) "none" else active.joinToString(", ") { "DC${it.key}" }
    }

    fun routeSummary(now: Long): String {
        val active = preferred.entries.filter { now - it.value.second < PREFERENCE_TTL_MS }
            .sortedBy { it.key }
        return if (active.isEmpty()) "none" else active.joinToString(", ") { "DC${it.key}=${it.value.first.tag}" }
    }

    fun serve(
        client: DataStream,
        label: String,
        dc: Int,
        isTestDc: Boolean,
        isMedia: Boolean,
        relayInit: ByteArray,
        ctx: CryptoCtx,
        protoInt: Int,
    ) {
        val dcKey = "$dc${if (isTestDc) "t" else ""}${if (isMedia) "m" else ""}"
        val mediaTag = if (isMedia) " media" else ""
        val now = System.currentTimeMillis()
        val started = now

        val target = config.dcRedirects[dc]
        val fallbackDst = (if (isTestDc) Const.DC_TEST_IPS else Const.DC_DEFAULT_IPS)[dc]
        val endpoints = if (fallbackDst != null) config.relayEndpoints() else emptyList()
        val wsPath = if (isTestDc) Const.WS_PATH_TEST else Const.WS_PATH
        val domains = Const.wsDomains(dc, isMedia)

        var blacklistUntil = wsBlacklistUntil[dcKey] ?: 0L
        if (blacklistUntil in 1..now) {
            wsBlacklistUntil.remove(dcKey, blacklistUntil)
            blacklistUntil = 0L
        }
        val hasDirect = target != null && blacklistUntil <= now
        if (target == null) {
            Logger.i("[$label] DC$dc not in config -> fallback")
        } else if (!hasDirect) {
            Logger.i("[$label] DC$dc$mediaTag WS blacklisted for ${(blacklistUntil - now) / 1000}s -> fallback")
        }

        val pref = preferred[dcKey]?.takeIf { now - it.second < PREFERENCE_TTL_MS }?.first
        val demoted = HashSet<Route>()
        for (r in Route.values()) if ((demotedUntil["$dcKey/${r.tag}"] ?: 0L) > now) demoted.add(r)
        // Upstream skips the direct route after a timeout; here it is only tried last.
        if (target != null && (now < (ipFailUntil[target] ?: 0L) || now < (dcFailUntil[dcKey] ?: 0L))) {
            demoted.add(Route.DIRECT)
        }

        // ------------------------------------------------ instant: pooled sockets
        var up: Upstream? = null
        val relayWanted = endpoints.isNotEmpty() && fallbackDst != null &&
            (config.relayFirst || pref == Route.RELAY || !hasDirect)
        if (!isTestDc && relayWanted && (config.relayFirst || pref == Route.RELAY)) {
            up = relayFromPool(dc, fallbackDst!!, endpoints)
        }
        // Pooled sockets were opened recently and are known good, so they are
        // used even when the direct route is demoted (upstream: "timed out, but
        // pool hit").
        if (up == null && !isTestDc && hasDirect) {
            wsPool.get(dc, isMedia, target!!, domains)?.let { ws ->
                up = Upstream(Route.POOL, "via $target", ws = ws, useSplitter = true)
            }
        }
        if (up == null && !isTestDc && relayWanted) {
            up = relayFromPool(dc, fallbackDst!!, endpoints)
        }

        // ------------------------------------------------------------- the race
        if (up == null) {
            val cfDomains = if (config.fallbackCfproxy && !isTestDc) {
                Balancer.getDomainsForDc(dc).take(RoutePlanner.MAX_PER_ROUTE)
            } else emptyList()
            val relayList = if (fallbackDst != null) relayPool.availableEndpoints(endpoints) else emptyList()

            val plan = RoutePlanner.plan(
                RoutePlanner.Input(
                    hasDirect = hasDirect,
                    frontingFirst = config.frontingFirst,
                    relayCount = relayList.size,
                    relayFirst = config.relayFirst,
                    cfCount = cfDomains.size,
                    hasTcp = fallbackDst != null,
                    preferred = pref,
                    demoted = demoted,
                )
            )
            val attempts = plan.mapNotNull { p ->
                when (p.route) {
                    Route.DIRECT -> directAttempt(p, target!!, domains, wsPath, dc, isMedia, isTestDc, sni = null)
                    Route.FRONTED -> directAttempt(
                        p, target!!, domains, wsPath, dc, isMedia, isTestDc,
                        sni = config.frontingSni.ifBlank { ProxyConfig.DEFAULT_FRONTING_SNI },
                    )
                    Route.RELAY -> relayList.getOrNull(p.index)?.let { relayAttempt(p, it, fallbackDst!!, dc, isTestDc, endpoints) }
                    Route.CF -> cfDomains.getOrNull(p.index)?.let { cfAttempt(p, it, dc) }
                    Route.TCP -> tcpAttempt(p, fallbackDst!!)
                    Route.POOL -> null
                }
            }
            if (attempts.isNotEmpty()) {
                Logger.d("[$label] DC$dc$mediaTag race: " + attempts.joinToString(" ") { "${it.route.tag}@${it.delayMs}" })
            }
            up = Racer.race(attempts, executor, RACE_DEADLINE_MS) { a, e ->
                onAttemptFailed(label, dc, dcKey, mediaTag, target, a, e)
            }
        }

        val chosen = up
        if (chosen == null) {
            Logger.w("[$label] DC$dc$mediaTag no route available")
            return
        }

        val connectMs = System.currentTimeMillis() - started
        chosen.onWin()
        onWon(dcKey, dc, isMedia, target, chosen)
        Stats.recordConnect(connectMs, chosen.route.tag)
        Logger.i("[$label] DC$dc$mediaTag -> ${chosen.route.tag} ${chosen.detail} (${connectMs}ms)")

        val session = try {
            if (chosen.ws != null) {
                val splitter = if (chosen.useSplitter) {
                    runCatching { MsgSplitter(relayInit, protoInt) }.getOrNull()
                } else null
                chosen.ws.setReadTimeout(0)
                chosen.ws.send(relayInit)
                Bridge.bridgeWsReencrypt(client, chosen.ws, label, ctx, dc, isMedia, splitter)
            } else {
                val remote = SocketStream(chosen.tcp!!, 32 * 1024)
                remote.write(relayInit)
                remote.flush()
                Bridge.bridgeTcpReencrypt(client, remote, label, ctx)
            }
        } catch (e: Exception) {
            chosen.close()
            throw e
        }
        onSessionEnd(label, dcKey, chosen.route, session)
    }

    // --------------------------------------------------------------- attempts

    private fun directAttempt(
        p: RoutePlanner.Planned,
        target: String,
        domains: List<String>,
        wsPath: String,
        dc: Int,
        isMedia: Boolean,
        isTestDc: Boolean,
        sni: String?,
    ): Attempt {
        val route = if (sni == null) Route.DIRECT else Route.FRONTED
        return Attempt(route, "via $target", p.delayMs) {
            for (domain in domains) {
                try {
                    val ws = RawWebSocket.connect(
                        host = target, domain = domain, timeoutMs = HANDSHAKE_TIMEOUT_MS,
                        path = wsPath, sni = sni, bufferSize = config.bufferSize,
                        connectTimeoutMs = CONNECT_TIMEOUT_MS,
                    )
                    return@Attempt Upstream(
                        route, "wss://$domain$wsPath via $target", ws = ws, useSplitter = true,
                        recycle = if (isTestDc) null else ({ wsPool.offer(dc, isMedia, ws) }),
                    )
                } catch (e: WsHandshakeError) {
                    if (!e.isRedirect) throw e
                    Logger.w("DC$dc${if (isMedia) " media" else ""} got ${e.statusCode} from $domain -> ${e.location ?: "?"}")
                }
            }
            throw AllRedirects(dc)
        }
    }

    private fun relayAttempt(
        p: RoutePlanner.Planned,
        ep: RelayEndpoint,
        dst: String,
        dc: Int,
        isTestDc: Boolean,
        all: List<RelayEndpoint>,
    ): Attempt = Attempt(Route.RELAY, ep.id, p.delayMs) {
        val ws = try {
            ep.connect(dst, dc, HANDSHAKE_TIMEOUT_MS, config.bufferSize, CONNECT_TIMEOUT_MS)
        } catch (e: Exception) {
            relayPool.reportFailure(ep, e)
            throw e
        }
        Upstream(
            Route.RELAY, "$ep for $dst", ws = ws, useSplitter = false,
            onWin = {
                relayPool.reportSuccess(ep)
                if (!isTestDc) relayPool.ensureWarm(dc, dst, all)
            },
        )
    }

    private fun cfAttempt(p: RoutePlanner.Planned, base: String, dc: Int): Attempt {
        val domain = "kws$dc.$base"
        return Attempt(Route.CF, domain, p.delayMs) {
            val ws = RawWebSocket.connect(
                host = domain, domain = domain, timeoutMs = HANDSHAKE_TIMEOUT_MS,
                bufferSize = config.bufferSize, secure = !config.disableSecure,
                connectTimeoutMs = CONNECT_TIMEOUT_MS,
            )
            Upstream(
                Route.CF, domain, ws = ws, useSplitter = true,
                onWin = {
                    if (Balancer.updateDomainForDc(dc, base)) Logger.i("Switched active CF domain for DC$dc")
                },
            )
        }
    }

    private fun tcpAttempt(p: RoutePlanner.Planned, dst: String): Attempt =
        Attempt(Route.TCP, "$dst:443", p.delayMs) {
            val s = Tls.connectPlain(dst, 443, CONNECT_TIMEOUT_MS, config.bufferSize)
            Upstream(Route.TCP, "$dst:443", tcp = s)
        }

    private fun relayFromPool(dc: Int, dst: String, endpoints: List<RelayEndpoint>): Upstream? {
        val pooled = relayPool.get(dc, dst, endpoints) ?: return null
        return Upstream(Route.RELAY, "${pooled.endpoint} (pooled)", ws = pooled.ws, useSplitter = false)
    }

    // ------------------------------------------------------------ bookkeeping

    private fun onAttemptFailed(
        label: String,
        dc: Int,
        dcKey: String,
        mediaTag: String,
        target: String?,
        a: Attempt,
        e: Throwable,
    ) {
        val now = System.currentTimeMillis()
        val what = when (e) {
            is SocketTimeoutException -> "timed out"
            is WsHandshakeError -> e.statusLine
            else -> e.toString().take(120)
        }
        when (a.route) {
            Route.DIRECT, Route.FRONTED -> {
                Stats.wsErrors.incrementAndGet()
                when {
                    e is AllRedirects -> {
                        wsBlacklistUntil[dcKey] = now + WS_BLACKLIST_COOLDOWN_MS
                        Logger.w("[$label] DC$dc$mediaTag blacklisted for WS for ${WS_BLACKLIST_COOLDOWN_MS / 1000}s (all 302)")
                    }
                    a.route == Route.DIRECT && e is SocketTimeoutException && target != null -> {
                        ipFailUntil[target] = now + IP_FAIL_COOLDOWN_MS
                        Logger.i("[$label] DC$dc$mediaTag WS connect to $target timed out, deprioritized")
                    }
                    a.route == Route.DIRECT -> {
                        dcFailUntil[dcKey] = now + DC_FAIL_COOLDOWN_MS
                        Logger.i("[$label] DC$dc$mediaTag WS failed ($what)")
                    }
                    else -> Logger.i("[$label] DC$dc$mediaTag fronted WS failed ($what)")
                }
            }
            else -> Logger.i("[$label] DC$dc$mediaTag ${a.route.tag} ${a.detail} failed ($what)")
        }
    }

    private fun onWon(dcKey: String, dc: Int, isMedia: Boolean, target: String?, up: Upstream) {
        val now = System.currentTimeMillis()
        when (up.route) {
            Route.POOL, Route.DIRECT, Route.FRONTED -> {
                if (target != null) ipFailUntil.remove(target)
                wsPool.reportSuccess(dc, isMedia)
                Stats.connectionsWs.incrementAndGet()
                if (up.route == Route.FRONTED) Stats.connectionsFronting.incrementAndGet()
            }
            Route.RELAY -> Stats.connectionsRelay.incrementAndGet()
            Route.CF -> Stats.connectionsCfproxy.incrementAndGet()
            Route.TCP -> Stats.connectionsTcpFallback.incrementAndGet()
        }
        val remembered = if (up.route == Route.POOL) Route.DIRECT else up.route
        preferred[dcKey] = remembered to now
        demotedUntil.remove("$dcKey/${remembered.tag}")
    }

    private fun onSessionEnd(label: String, dcKey: String, route: Route, s: Bridge.Session) {
        if (s.downBytes > 0 || s.upBytes == 0L || s.durationMs > DEAD_SESSION_MS) return
        // Upstream accepted the connection but never answered: typical of a
        // DPI box that lets the handshake through and then drops the flow.
        val r = if (route == Route.POOL) Route.DIRECT else route
        demotedUntil["$dcKey/${r.tag}"] = System.currentTimeMillis() + DEMOTE_MS
        preferred.computeIfPresent(dcKey) { _, v -> if (v.first == r) null else v }
        Logger.w("[$label] ${r.tag} route for DC$dcKey carried no data, demoted for ${DEMOTE_MS / 1000}s")
    }
}
