package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.WsHandshakeError
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService

/**
 * Port of proxy/pool.py — pre-warmed upstream WS connections so a new Telegram
 * connection does not pay for a TLS handshake.
 *
 * The Python version uses asyncio tasks; here refills run on a shared executor
 * and expiry is checked lazily on get() plus by a periodic sweeper started by
 * [ProxyEngine].
 */
class WsPool(private val executor: ExecutorService) {

    companion object {
        const val WS_POOL_MAX_AGE_MS = 120_000L
        const val REFILL_BACKOFF_INITIAL_MS = 60_000L
        const val REFILL_BACKOFF_MAX_MS = 3_600_000L
    }

    private data class Key(val dc: Int, val isMedia: Boolean)
    private class Entry(val ws: RawWebSocket, val createdAt: Long)

    private val idle = ConcurrentHashMap<Key, ArrayDeque<Entry>>()

    // Collections.newSetFromMap instead of ConcurrentHashMap.newKeySet: the
    // latter's KeySetView methods are only desugared from API 24.
    private val refilling: MutableSet<Key> =
        java.util.Collections.newSetFromMap(ConcurrentHashMap<Key, Boolean>())
    private val refillFailures = ConcurrentHashMap<Key, Int>()
    private val refillAfter = ConcurrentHashMap<Key, Long>()

    @Volatile
    var tryFrontingFirst: Boolean = false
        private set

    @Volatile
    private var config: ProxyConfig = ProxyConfig()

    @Volatile
    private var stopped = false

    fun configure(cfg: ProxyConfig) {
        config = cfg
        // Fronting-first skips the plain attempt that a filtering network would
        // just time out on, saving several seconds per connection.
        if (cfg.frontingFirst) tryFrontingFirst = true
    }

    private fun bucketFor(key: Key): ArrayDeque<Entry> =
        idle.getOrPut(key) { ArrayDeque() }

    fun get(
        dc: Int,
        isMedia: Boolean,
        targetIp: String,
        domains: List<String>,
        allowRefill: Boolean = true,
    ): RawWebSocket? {
        val key = Key(dc, isMedia)
        val now = System.currentTimeMillis()
        val bucket = bucketFor(key)

        while (true) {
            val entry = synchronized(bucket) { bucket.pollFirst() } ?: break
            val age = now - entry.createdAt
            if (age > WS_POOL_MAX_AGE_MS || entry.ws.isBroken) {
                closeQuiet(entry.ws)
                continue
            }
            Stats.poolHits.incrementAndGet()
            val left = synchronized(bucket) { bucket.size }
            Logger.d(
                "WS pool hit DC$dc${if (isMedia) "m" else ""} " +
                    "(age=${age / 1000.0}s, left=$left)"
            )
            reportSuccess(dc, isMedia)
            if (allowRefill) scheduleRefill(key, targetIp, domains)
            return entry.ws
        }

        Stats.poolMisses.incrementAndGet()
        if (allowRefill) scheduleRefill(key, targetIp, domains)
        return null
    }

    fun reportSuccess(dc: Int, isMedia: Boolean) {
        val key = Key(dc, isMedia)
        refillFailures.remove(key)
        refillAfter.remove(key)
    }

    private fun scheduleRefill(key: Key, targetIp: String, domains: List<String>) {
        if (stopped) return
        if (System.currentTimeMillis() < (refillAfter[key] ?: 0L)) return
        if (!refilling.add(key)) return
        runCatching {
            executor.execute { refill(key, targetIp, domains) }
        }.onFailure { refilling.remove(key) }
    }

    private fun refill(key: Key, targetIp: String, domains: List<String>) {
        try {
            if (stopped) return
            val bucket = bucketFor(key)
            val needed = config.poolSize - synchronized(bucket) { bucket.size }
            if (needed <= 0) return

            var connected = 0
            for (i in 0 until needed) {
                if (stopped) break
                val ws = connectOne(targetIp, domains) ?: break
                synchronized(bucket) { bucket.addLast(Entry(ws, System.currentTimeMillis())) }
                connected++
            }

            if (connected > 0) {
                reportSuccess(key.dc, key.isMedia)
            } else {
                val failures = (refillFailures[key] ?: 0) + 1
                refillFailures[key] = failures
                val delay = minOf(
                    REFILL_BACKOFF_INITIAL_MS shl minOf(failures - 1, 6),
                    REFILL_BACKOFF_MAX_MS,
                )
                refillAfter[key] = System.currentTimeMillis() + delay
                Logger.i(
                    "WS pool refill failed for DC${key.dc}${if (key.isMedia) "m" else ""}, " +
                        "retry in ${delay / 1000}s"
                )
            }
            Logger.d(
                "WS pool refilled DC${key.dc}${if (key.isMedia) "m" else ""}: " +
                    "${synchronized(bucket) { bucket.size }} ready"
            )
        } finally {
            refilling.remove(key)
        }
    }

    private fun connectOne(targetIp: String, domains: List<String>): RawWebSocket? {
        for (domain in domains) {
            if (tryFrontingFirst) {
                val fronted = connectFronted(targetIp, domain)
                if (fronted != null) return fronted
            }
            try {
                val ws = RawWebSocket.connect(
                    host = targetIp, domain = domain, timeoutMs = 8_000,
                    bufferSize = config.bufferSize,
                )
                tryFrontingFirst = false
                return ws
            } catch (e: java.net.SocketTimeoutException) {
                if (tryFrontingFirst) return null
                return connectFronted(targetIp, domain)
            } catch (e: WsHandshakeError) {
                if (e.isRedirect) continue
                return null
            } catch (e: Exception) {
                return null
            }
        }
        return null
    }

    private fun connectFronted(targetIp: String, domain: String): RawWebSocket? {
        val ws = try {
            RawWebSocket.connect(
                host = targetIp, domain = domain, timeoutMs = 7_000,
                sni = config.frontingSni.ifBlank { ProxyConfig.DEFAULT_FRONTING_SNI },
                bufferSize = config.bufferSize,
            )
        } catch (e: Exception) {
            return null
        }
        Stats.connectionsFronting.incrementAndGet()
        tryFrontingFirst = true
        return ws
    }

    /** Drops expired sockets and tops the buckets back up. */
    fun sweep() {
        if (stopped) return
        val now = System.currentTimeMillis()
        for ((key, bucket) in idle) {
            val expired = ArrayList<RawWebSocket>()
            synchronized(bucket) {
                val ready = ArrayList<Entry>(bucket.size)
                while (true) {
                    val e = bucket.pollFirst() ?: break
                    if (now - e.createdAt >= WS_POOL_MAX_AGE_MS || e.ws.isBroken) {
                        expired.add(e.ws)
                    } else {
                        ready.add(e)
                    }
                }
                for (e in ready) bucket.addLast(e)
            }
            if (expired.isEmpty()) continue
            for (ws in expired) closeQuiet(ws)
            Logger.d(
                "WS pool rotated DC${key.dc}${if (key.isMedia) "m" else ""}: " +
                    "${expired.size} stale, ${synchronized(bucket) { bucket.size }} ready"
            )
            val targetIp = config.dcRedirects[key.dc] ?: continue
            scheduleRefill(key, targetIp, Const.wsDomains(key.dc, key.isMedia))
        }
    }

    fun warmup() {
        stopped = false
        for ((dc, targetIp) in config.dcRedirects) {
            for (isMedia in listOf(false, true)) {
                scheduleRefill(Key(dc, isMedia), targetIp, Const.wsDomains(dc, isMedia))
            }
        }
        Logger.i("WS pool warmup started for ${config.dcRedirects.size} DC(s)")
    }

    fun reset() {
        stopped = true
        for ((_, bucket) in idle) {
            synchronized(bucket) {
                while (true) {
                    val e = bucket.pollFirst() ?: break
                    closeQuiet(e.ws)
                }
            }
        }
        idle.clear()
        refilling.clear()
        refillFailures.clear()
        refillAfter.clear()
        tryFrontingFirst = false
    }

    private fun closeQuiet(ws: RawWebSocket) {
        runCatching { executor.execute { runCatching { ws.close() } } }
            .onFailure { runCatching { ws.abort() } }
    }
}

/**
 * Port of proxy/pool.py::_CfWorkerPool — one pre-opened Cloudflare Worker
 * connection per DC, used by the CF worker fallback path.
 */
class CfWorkerPool(private val executor: ExecutorService) {

    companion object {
        const val WS_POOL_MAX_AGE_MS = 100_000L
        const val PER_DC_LIMIT = 1
    }

    private class Entry(val ws: RawWebSocket, val createdAt: Long, val workerDomain: String)

    private val idle = ConcurrentHashMap<Int, ArrayDeque<Entry>>()
    private val refilling: MutableSet<Int> =
        java.util.Collections.newSetFromMap(ConcurrentHashMap<Int, Boolean>())
    private val exhaustedUntil = ConcurrentHashMap<String, Long>()

    @Volatile
    private var config: ProxyConfig = ProxyConfig()

    @Volatile
    private var stopped = false

    fun configure(cfg: ProxyConfig) {
        config = cfg
    }

    class Pooled(val ws: RawWebSocket, val workerDomain: String)

    fun get(dc: Int, fallbackDst: String, workerDomains: List<String>): Pooled? {
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
                "CF worker pool hit DC$dc via ${e.workerDomain} " +
                    "(age=${age / 1000.0}s, left=${synchronized(bucket) { bucket.size }})"
            )
            scheduleRefill(dc, fallbackDst, workerDomains)
            return Pooled(e.ws, e.workerDomain)
        }

        Stats.cfPoolMisses.incrementAndGet()
        return null
    }

    private fun scheduleRefill(dc: Int, fallbackDst: String, workerDomains: List<String>) {
        if (stopped) return
        if (!refilling.add(dc)) return
        runCatching {
            executor.execute { refill(dc, fallbackDst, workerDomains.toList()) }
        }.onFailure { refilling.remove(dc) }
    }

    private fun refill(dc: Int, fallbackDst: String, workerDomains: List<String>) {
        try {
            if (stopped) return
            val bucket = idle.getOrPut(dc) { ArrayDeque() }
            val targetSize = minOf(config.poolSize, PER_DC_LIMIT)
            val needed = targetSize - synchronized(bucket) { bucket.size }
            if (needed <= 0) return

            for (i in 0 until needed) {
                if (stopped) break
                val connected = connectOne(workerDomains, fallbackDst, dc) ?: break
                synchronized(bucket) {
                    bucket.addLast(
                        Entry(connected.ws, System.currentTimeMillis(), connected.workerDomain)
                    )
                }
            }
            Logger.d("CF worker pool refilled DC$dc: ${synchronized(bucket) { bucket.size }} ready")
        } finally {
            refilling.remove(dc)
        }
    }

    private fun connectOne(workerDomains: List<String>, fallbackDst: String, dc: Int): Pooled? {
        val path = "/apiws?dst=${urlEncode(fallbackDst)}&dc=$dc"
        for (workerDomain in availableDomains(workerDomains)) {
            try {
                val ws = RawWebSocket.connect(
                    host = workerDomain, domain = workerDomain, timeoutMs = 8_000,
                    path = path, bufferSize = config.bufferSize,
                )
                return Pooled(ws, workerDomain)
            } catch (e: Exception) {
                reportFailure(workerDomain, e)
            }
        }
        return null
    }

    fun availableDomains(workerDomains: List<String>): List<String> {
        val now = System.currentTimeMillis()
        val domains = ArrayList<String>()
        for (domain in workerDomains) {
            if (domains.contains(domain)) continue
            val until = exhaustedUntil[domain] ?: 0L
            if (until > now) continue
            if (until != 0L) exhaustedUntil.remove(domain)
            domains.add(domain)
        }
        domains.shuffle()
        return domains
    }

    /**
     * Mirrors the Python version, which currently ignores the failure
     * (TODO upstream: verify the status code sent after the daily limit).
     */
    @Suppress("UNUSED_PARAMETER")
    fun reportFailure(workerDomain: String, exc: Exception) {
        // no-op
    }

    fun warmup() {
        stopped = false
        if (config.cfproxyWorkerDomains.isEmpty()) return
        val cfFallbacks = Const.DC_DEFAULT_IPS.filterKeys { it !in config.dcRedirects }
        if (cfFallbacks.isEmpty()) return

        val workerDomains = config.cfproxyWorkerDomains.toList()
        for ((dc, fallbackDst) in cfFallbacks) {
            scheduleRefill(dc, fallbackDst, workerDomains)
        }
        Logger.i("CF worker pool warmup started for ${cfFallbacks.size} DC(s)")
    }

    fun reset() {
        stopped = true
        for ((_, bucket) in idle) {
            synchronized(bucket) {
                while (true) {
                    val e = bucket.pollFirst() ?: break
                    runCatching { e.ws.abort() }
                }
            }
        }
        idle.clear()
        refilling.clear()
        exhaustedUntil.clear()
    }

    private fun urlEncode(s: String): String =
        java.net.URLEncoder.encode(s, "UTF-8")
}
