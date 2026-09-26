package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.Tls
import com.flowseal.tgwsproxy.net.WsHandshakeError
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService

/**
 * A WebSocket relay that forwards raw TCP to a Telegram DC: either upstream's
 * Cloudflare Worker (docs/CfWorker.md) or a self-hosted `tg_ws_relay.py`.
 * Both speak the same protocol: `GET <path>?dst=<dc ip>&dc=<n>` upgraded to a
 * WebSocket whose binary frames are the TCP stream.
 *
 * The self-hosted variant is what gets through mobile "whitelist" filtering:
 * only a server whose IP (and, on some networks, SNI) is on the allowed list
 * can be reached at all, so the relay has to live there. The endpoint syntax
 * lets the connect address, the TLS name and the Host header differ, which is
 * also what fronting through a whitelisted CDN needs.
 *
 * Syntax (one entry per line or comma):
 *
 *     worker.name.workers.dev                     wss, port 443, path /apiws
 *     wss://relay.example.ru/apiws
 *     ws://203.0.113.7:8080                       plain WebSocket
 *     wss://relay.example.ru?ip=203.0.113.7&sni=vk.com&key=SECRET&verify=0
 *
 * `ip` connects there instead of resolving the host, `sni` overrides the TLS
 * server name (the certificate chain is still checked, the name is not),
 * `key` is passed to the relay for authentication, `verify=0` accepts any
 * certificate (self-signed relays).
 */
class RelayEndpoint(
    val host: String,
    val port: Int,
    val secure: Boolean,
    val path: String,
    val connectAddr: String,
    val sni: String?,
    val key: String?,
    val verifyCert: Boolean,
) {
    /** Stable identity, used for logs and per-endpoint bookkeeping. */
    val id: String = buildString {
        append(if (secure) "wss://" else "ws://").append(host)
        if (port != (if (secure) 443 else 80)) append(':').append(port)
        append(path)
        if (connectAddr != host) append("@").append(connectAddr)
    }

    fun requestPath(dst: String, dc: Int): String {
        val sep = if (path.contains('?')) '&' else '?'
        val sb = StringBuilder(path).append(sep)
            .append("dst=").append(enc(dst)).append("&dc=").append(dc)
        if (!key.isNullOrEmpty()) sb.append("&key=").append(enc(key))
        return sb.toString()
    }

    fun verifyMode(): Tls.Verify = when {
        !verifyCert -> Tls.Verify.NONE
        sni != null && sni != host -> Tls.Verify.CHAIN
        else -> Tls.Verify.FULL
    }

    @Throws(Exception::class)
    fun connect(dst: String, dc: Int, timeoutMs: Int, bufferSize: Int, connectTimeoutMs: Int = timeoutMs): RawWebSocket =
        RawWebSocket.connect(
            host = connectAddr,
            domain = host,
            timeoutMs = timeoutMs,
            path = requestPath(dst, dc),
            sni = sni,
            bufferSize = bufferSize,
            secure = secure,
            port = port,
            verify = verifyMode(),
            connectTimeoutMs = connectTimeoutMs,
        )

    override fun toString(): String = id
    override fun equals(other: Any?): Boolean = other is RelayEndpoint && other.id == id
    override fun hashCode(): Int = id.hashCode()

    companion object {
        const val DEFAULT_PATH = "/apiws"

        private fun enc(s: String): String = java.net.URLEncoder.encode(s, "UTF-8")

        /**
         * Parses one entry. [defaultSecure] applies when no scheme is given
         * (upstream's `--no-secure` switches bare worker domains to port 80).
         * Returns null for anything malformed.
         */
        fun parse(raw: String, defaultSecure: Boolean = true): RelayEndpoint? {
            var s = raw.trim()
            if (s.isEmpty() || s.startsWith("#")) return null

            val secure: Boolean
            val schemeEnd = s.indexOf("://")
            if (schemeEnd >= 0) {
                secure = when (s.substring(0, schemeEnd).lowercase()) {
                    "wss", "https" -> true
                    "ws", "http" -> false
                    else -> return null
                }
                s = s.substring(schemeEnd + 3)
            } else {
                secure = defaultSecure
            }

            val queryStart = s.indexOf('?')
            val query = if (queryStart >= 0) s.substring(queryStart + 1) else ""
            val beforeQuery = if (queryStart >= 0) s.substring(0, queryStart) else s
            val slash = beforeQuery.indexOf('/')
            val authority = if (slash >= 0) beforeQuery.substring(0, slash) else beforeQuery
            val path = if (slash >= 0) beforeQuery.substring(slash) else DEFAULT_PATH

            return parseWithPath(authority, path, query, secure)
        }

        private fun parseWithPath(authority: String, path: String, query: String, secure: Boolean): RelayEndpoint? {
            if (authority.isEmpty() || authority.contains('@')) return null
            val colon = authority.lastIndexOf(':')
            val host = (if (colon >= 0) authority.substring(0, colon) else authority).lowercase()
            val port = if (colon >= 0) {
                authority.substring(colon + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            } else {
                if (secure) 443 else 80
            }
            if (!ProxyConfig.isValidDomain(host) && !ProxyConfig.isIpv4(host)) return null
            if (path.any { it.isWhitespace() }) return null

            var ip: String? = null
            var sni: String? = null
            var key: String? = null
            var verify = true
            val extra = ArrayList<String>()
            for (pair in query.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                val k = (if (eq >= 0) pair.substring(0, eq) else pair).lowercase()
                val v = if (eq >= 0) java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8") else ""
                when (k) {
                    "ip", "addr" -> ip = v.takeIf { ProxyConfig.isIpv4(it) } ?: return null
                    "sni" -> sni = v.lowercase().takeIf { ProxyConfig.isValidDomain(it) } ?: return null
                    "key", "token" -> key = v.takeIf { it.isNotEmpty() }
                    "verify", "insecure" -> {
                        val on = v !in setOf("0", "false", "no", "off")
                        verify = if (k == "insecure") !on else on
                    }
                    else -> extra.add(pair)
                }
            }
            // Unknown parameters stay part of the request path.
            val fullPath = if (extra.isEmpty()) path else path + "?" + extra.joinToString("&")

            return RelayEndpoint(
                host = host,
                port = port,
                secure = secure,
                path = fullPath,
                connectAddr = ip ?: host,
                sni = sni,
                key = key,
                verifyCert = verify,
            )
        }

        fun parseList(entries: List<String>, defaultSecure: Boolean = true): List<RelayEndpoint> {
            val out = LinkedHashMap<String, RelayEndpoint>()
            for (e in entries.flatMap { it.split('\n', ',', ';', ' ') }) {
                val ep = parse(e, defaultSecure) ?: continue
                out.putIfAbsent(ep.id, ep)
            }
            return out.values.toList()
        }

        /** Entries that do not parse, for validation messages. */
        fun invalidEntries(entries: List<String>): List<String> =
            entries.flatMap { it.split('\n', ',', ';', ' ') }
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") && parse(it) == null }
    }
}

/**
 * Port of proxy/pool.py::_CfWorkerPool, generalized to any [RelayEndpoint]:
 * a pre-opened relay connection per DC, so the relay route does not pay a
 * TLS + WebSocket handshake on every new Telegram connection.
 */
class RelayPool(private val executor: ExecutorService) {

    companion object {
        const val WS_POOL_MAX_AGE_MS = 100_000L
        const val PER_DC_LIMIT = 2
    }

    private class Entry(val ws: RawWebSocket, val createdAt: Long, val endpoint: RelayEndpoint)

    class Pooled(val ws: RawWebSocket, val endpoint: RelayEndpoint)

    private val idle = ConcurrentHashMap<Int, ArrayDeque<Entry>>()
    private val refilling: MutableSet<Int> =
        java.util.Collections.newSetFromMap(ConcurrentHashMap<Int, Boolean>())
    private val exhaustedUntil = ConcurrentHashMap<String, Long>()
    private val failedUntil = ConcurrentHashMap<String, Long>()

    @Volatile
    private var config: ProxyConfig = ProxyConfig()

    @Volatile
    private var stopped = false

    fun configure(cfg: ProxyConfig) {
        config = cfg
    }

    fun get(dc: Int, dst: String, endpoints: List<RelayEndpoint>): Pooled? {
        val now = System.currentTimeMillis()
        val bucket = idle.getOrPut(dc) { ArrayDeque() }

        while (true) {
            val e = synchronized(bucket) { bucket.pollFirst() } ?: break
            val age = now - e.createdAt
            if (age > WS_POOL_MAX_AGE_MS || e.ws.isBroken) {
                runCatching { executor.execute { runCatching { e.ws.close() } } }
                continue
            }
            Stats.cfPoolHits.incrementAndGet()
            Logger.d(
                "Relay pool hit DC$dc via ${e.endpoint} " +
                    "(age=${age / 1000.0}s, left=${synchronized(bucket) { bucket.size }})"
            )
            scheduleRefill(dc, dst, endpoints)
            return Pooled(e.ws, e.endpoint)
        }

        Stats.cfPoolMisses.incrementAndGet()
        scheduleRefill(dc, dst, endpoints)
        return null
    }

    /** Keeps a warm connection for [dc]; called once the relay route wins. */
    fun ensureWarm(dc: Int, dst: String, endpoints: List<RelayEndpoint>) =
        scheduleRefill(dc, dst, endpoints)

    private fun scheduleRefill(dc: Int, dst: String, endpoints: List<RelayEndpoint>) {
        if (stopped || endpoints.isEmpty() || config.poolSize <= 0) return
        if (!refilling.add(dc)) return
        runCatching {
            executor.execute { refill(dc, dst, endpoints.toList()) }
        }.onFailure { refilling.remove(dc) }
    }

    private fun refill(dc: Int, dst: String, endpoints: List<RelayEndpoint>) {
        try {
            if (stopped) return
            val bucket = idle.getOrPut(dc) { ArrayDeque() }
            val targetSize = minOf(config.poolSize, PER_DC_LIMIT)
            val needed = targetSize - synchronized(bucket) { bucket.size }
            if (needed <= 0) return

            for (i in 0 until needed) {
                if (stopped) break
                val connected = connectOne(endpoints, dst, dc) ?: break
                if (stopped) {
                    connected.ws.abort()
                    break
                }
                synchronized(bucket) {
                    bucket.addLast(Entry(connected.ws, System.currentTimeMillis(), connected.endpoint))
                }
            }
            Logger.d("Relay pool refilled DC$dc: ${synchronized(bucket) { bucket.size }} ready")
        } finally {
            refilling.remove(dc)
        }
    }

    private fun connectOne(endpoints: List<RelayEndpoint>, dst: String, dc: Int): Pooled? {
        for (ep in availableEndpoints(endpoints)) {
            try {
                return Pooled(ep.connect(dst, dc, 8_000, config.bufferSize, 5_000), ep)
            } catch (e: Exception) {
                reportFailure(ep, e)
            }
        }
        return null
    }

    /** Usable endpoints, healthy ones first, shuffled within each group. */
    fun availableEndpoints(endpoints: List<RelayEndpoint>): List<RelayEndpoint> {
        val now = System.currentTimeMillis()
        val healthy = ArrayList<RelayEndpoint>()
        val suspect = ArrayList<RelayEndpoint>()
        for (ep in endpoints.distinct()) {
            val until = exhaustedUntil[ep.id] ?: 0L
            if (until > now) continue
            if (until != 0L) exhaustedUntil.remove(ep.id)
            if ((failedUntil[ep.id] ?: 0L) > now) suspect.add(ep) else healthy.add(ep)
        }
        healthy.shuffle()
        suspect.shuffle()
        return healthy + suspect
    }

    fun reportSuccess(ep: RelayEndpoint) {
        failedUntil.remove(ep.id)
    }

    /**
     * HTTP 429 from a Cloudflare Worker means the daily request quota is spent:
     * disable it until the next UTC day. Other failures only demote it briefly.
     */
    fun reportFailure(ep: RelayEndpoint, exc: Exception) {
        val now = System.currentTimeMillis()
        if (exc !is WsHandshakeError || exc.statusCode != 429) {
            failedUntil[ep.id] = now + 30_000L
            return
        }
        if ((exhaustedUntil[ep.id] ?: 0L) > now) return

        val until = now + (86_400_000L - now % 86_400_000L)
        exhaustedUntil[ep.id] = until
        Logger.w("Relay $ep reached its request limit, disabled for ${(until - now) / 1000}s")
    }

    /**
     * Upstream warms the worker pool for DCs that have no direct route. With
     * [allDcs] (relay-first / whitelist mode) every DC gets a warm connection.
     */
    fun warmup(endpoints: List<RelayEndpoint>, allDcs: Boolean) {
        stopped = false
        if (endpoints.isEmpty()) return
        val targets = if (allDcs) Const.DC_DEFAULT_IPS.filterKeys { it != 203 }
        else Const.DC_DEFAULT_IPS.filterKeys { it !in config.dcRedirects }
        if (targets.isEmpty()) return
        for ((dc, dst) in targets) scheduleRefill(dc, dst, endpoints)
        Logger.i("Relay pool warmup started for ${targets.size} DC(s)")
    }

    /** Drops idle connections, e.g. after a network change; keeps running. */
    fun flush() {
        for ((_, bucket) in idle) {
            synchronized(bucket) {
                while (true) {
                    val e = bucket.pollFirst() ?: break
                    runCatching { e.ws.abort() }
                }
            }
        }
        failedUntil.clear()
    }

    fun reset() {
        stopped = true
        flush()
        idle.clear()
        refilling.clear()
        exhaustedUntil.clear()
    }
}
