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
        // Mirrors upstream REFILL_BACKOFF_INITIAL = 1.0: a failed refill is
        // retried almost immediately, then backs off exponentially.
        const val REFILL_BACKOFF_INITIAL_MS = 1_000L
        const val REFILL_BACKOFF_MAX_MS = 3_600_000L
        const val REFILL_BACKOFF_MAX_SHIFT = 12
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

    /** Upstream 1.12.0 starts with the real SNI and remembers whichever worked. */
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
            scheduleRefill(key, targetIp, domains)
            return entry.ws
        }

        Stats.poolMisses.incrementAndGet()
        scheduleRefill(key, targetIp, domains)
        return null
    }

    /**
     * Takes an extra, already-open connection (a loser of the route race) when
     * the bucket has room. Returns false when the caller should close it.
     */
    fun offer(dc: Int, isMedia: Boolean, ws: RawWebSocket): Boolean {
        if (stopped || ws.isBroken) return false
        val bucket = bucketFor(Key(dc, isMedia))
        synchronized(bucket) {
            if (bucket.size >= config.poolSize) return false
            bucket.addLast(Entry(ws, System.currentTimeMillis()))
        }
        Logger.d("WS pool adopted spare connection DC$dc${if (isMedia) "m" else ""}")
        return true
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
                    REFILL_BACKOFF_INITIAL_MS * (1L shl minOf(failures - 1, REFILL_BACKOFF_MAX_SHIFT)),
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
                    bufferSize = config.bufferSize, connectTimeoutMs = 5_000,
                )
                tryFrontingFirst = false
                return ws
            } catch (e: java.net.SocketTimeoutException) {
                if (tryFrontingFirst) return null
                return connectFronted(targetIp, domain)
            } catch (e: java.net.SocketException) {
                // Connection reset mid-handshake: same treatment as a timeout,
                // mirrors upstream catching ConnectionResetError next to TimeoutError.
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
                bufferSize = config.bufferSize, connectTimeoutMs = 5_000,
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
            // Upstream refills after rotation only when the bucket is short.
            if (synchronized(bucket) { bucket.size } >= config.poolSize) continue
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

    /**
     * Drops idle sockets and refill backoff but keeps the pool running; used
     * after a network change, when every open socket belongs to the old network.
     */
    fun flush() {
        for ((_, bucket) in idle) {
            synchronized(bucket) {
                while (true) {
                    val e = bucket.pollFirst() ?: break
                    e.ws.abort()
                }
            }
        }
        refillFailures.clear()
        refillAfter.clear()
        // Learned per network; configure() re-applies fronting-first if set.
        tryFrontingFirst = false
    }

    fun reset() {
        stopped = true
        // flush() also drops the fronting preference: upstream 1.12.0 starts
        // with try_fronting_first = False, configure() turns it on when
        // fronting-first is set (or forced on mobile data).
        flush()
        idle.clear()
        refilling.clear()
    }

    private fun closeQuiet(ws: RawWebSocket) {
        runCatching { executor.execute { runCatching { ws.close() } } }
            .onFailure { runCatching { ws.abort() } }
    }
}
