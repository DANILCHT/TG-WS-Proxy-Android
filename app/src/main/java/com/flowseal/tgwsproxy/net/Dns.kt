package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Crypto
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.ProxyConfig
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit

/**
 * Host name resolution for upstream connections.
 *
 * Android's own resolver cache keeps entries for ~2 seconds, so every new
 * CF-proxy or relay connection used to pay for a fresh lookup. Answers are
 * cached here for [TTL_MS] instead.
 *
 * When the system resolver fails, times out, or returns an obviously bogus
 * answer (loopback, private ranges, 0.0.0.0 — a common way to "block" a name),
 * the name is resolved over DNS-over-HTTPS. DoH servers are contacted by IP, so
 * this does not depend on the system resolver at all.
 */
object Dns {

    private const val TTL_MS = 10 * 60_000L
    private const val SYSTEM_TIMEOUT_MS = 3_000L
    private const val DOH_TIMEOUT_MS = 4_000

    /** IP, TLS name and path of each DoH server; queried in parallel. */
    internal class DohServer(val ip: String, val host: String, val path: String)

    private val DOH_SERVERS = listOf(
        // Yandex first: its addresses stay reachable on whitelisted networks.
        DohServer("77.88.8.8", "common.dot.dns.yandex.net", "/dns-query"),
        DohServer("1.1.1.1", "cloudflare-dns.com", "/dns-query"),
        DohServer("8.8.8.8", "dns.google", "/dns-query"),
    )

    private class Entry(val addrs: List<InetAddress>, val at: Long, val ttlMs: Long = TTL_MS)

    /** Fallback answers (DoH failed) are kept briefly so DoH is retried soon, not on every connect. */
    private const val FALLBACK_TTL_MS = 60_000L

    private val cache = ConcurrentHashMap<String, Entry>()

    private val executor = Executors.newCachedThreadPool(object : ThreadFactory {
        override fun newThread(r: Runnable): Thread =
            Thread(r, "dns").apply { isDaemon = true }
    })

    @Volatile
    var dohEnabled: Boolean = true

    /**
     * Names that must resolve to Cloudflare (the CF proxy domains, Workers).
     * A provider that "blocks" such a name by answering with its own stub
     * address gets bypassed through DoH.
     */
    @Volatile
    var expectCloudflare: (String) -> Boolean = { false }

    /** Cloudflare's published IPv4 ranges (cloudflare.com/ips-v4). */
    private val CLOUDFLARE_V4: List<Pair<Int, Int>> = listOf(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ).map { cidr ->
        val (ip, bits) = cidr.split('/')
        val mask = if (bits.toInt() == 0) 0 else -1 shl (32 - bits.toInt())
        (ipv4ToInt(ip) and mask) to mask
    }

    private fun ipv4ToInt(ip: String): Int =
        ip.split('.').fold(0) { acc, part -> (acc shl 8) or part.toInt() }

    internal fun isCloudflare(a: InetAddress): Boolean {
        val b = a.address
        if (b.size != 4) return false
        val v = ((b[0].toInt() and 0xFF) shl 24) or ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
        return CLOUDFLARE_V4.any { (net, mask) -> (v and mask) == net }
    }

    fun clear() = cache.clear()

    /**
     * Resolves [host] to IPv4 addresses. [systemLookup] performs the platform
     * lookup (bound to the right network by the caller).
     */
    @Throws(UnknownHostException::class)
    fun resolve(host: String, systemLookup: (String) -> Array<InetAddress>): List<InetAddress> {
        if (ProxyConfig.isIpv4(host)) return listOf(InetAddress.getByName(host))
        val key = host.lowercase()
        val now = System.currentTimeMillis()
        cache[key]?.let { if (now - it.at < it.ttlMs) return it.addrs }

        val system = runCatching {
            executor.submit(Callable { systemLookup(host) })
                .get(SYSTEM_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .filterIsInstance<Inet4Address>()
        }.getOrElse { emptyList() }

        val usable = system.filter { isPublic(it) }
        val wantCf = runCatching { expectCloudflare(key) }.getOrDefault(false)
        val good = if (wantCf) usable.filter { isCloudflare(it) } else usable
        if (good.isNotEmpty()) {
            cache[key] = Entry(good, now)
            return good
        }

        if (dohEnabled) {
            val doh = resolveDoh(host)
            val dohGood = if (wantCf) doh.filter { isCloudflare(it) } else doh
            if (dohGood.isNotEmpty()) {
                Logger.d(
                    "DNS: $host resolved over DoH (system answer: ${system.size} " +
                        "${if (wantCf) "not Cloudflare" else "unusable"})"
                )
                cache[key] = Entry(dohGood, now)
                return dohGood
            }
            if (doh.isNotEmpty() && usable.isEmpty()) return doh
        }

        // Nothing better: a public non-Cloudflare answer is still worth a try,
        // and a private one may be legitimate (a relay on a LAN); else fail.
        if (usable.isNotEmpty()) {
            cache[key] = Entry(usable, now, FALLBACK_TTL_MS)
            return usable
        }
        if (system.isNotEmpty()) return system
        throw UnknownHostException(host)
    }

    private fun isPublic(a: InetAddress): Boolean =
        !(a.isAnyLocalAddress || a.isLoopbackAddress || a.isLinkLocalAddress ||
            a.isSiteLocalAddress || a.isMulticastAddress)

    private fun resolveDoh(host: String): List<InetAddress> {
        val ecs = ExecutorCompletionService<List<InetAddress>>(executor)
        val futures = DOH_SERVERS.map { s -> ecs.submit { queryDoh(s, host) } }
        try {
            val deadline = System.currentTimeMillis() + DOH_TIMEOUT_MS + 1_000
            repeat(futures.size) {
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) return emptyList()
                val f = ecs.poll(left, TimeUnit.MILLISECONDS) ?: return emptyList()
                val r = runCatching { f.get() }.getOrNull()
                if (!r.isNullOrEmpty()) return r
            }
        } finally {
            futures.forEach { it.cancel(true) }
        }
        return emptyList()
    }

    private fun queryDoh(server: DohServer, host: String): List<InetAddress> {
        val query = buildQuery(host, Crypto.randomInt(0xFFFF))
        val path = server.path + "?dns=" + base64Url(query)
        val resp = HttpLite.request(
            HttpLite.Request(
                url = "https://${server.host}$path",
                connectAddr = server.ip,
                timeoutMs = DOH_TIMEOUT_MS,
                headers = mapOf("Accept" to "application/dns-message"),
                maxBytes = 64 * 1024,
                useDns = false,
            )
        )
        if (resp.status != 200) return emptyList()
        return parseAnswer(resp.body).map { InetAddress.getByAddress(host, it) }
    }

    // ------------------------------------------------------------ wire format

    /** RFC 1035 query for an A record with recursion desired. */
    internal fun buildQuery(host: String, id: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((id shr 8) and 0xFF); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00) // RD
        out.write(0); out.write(1)       // QDCOUNT
        repeat(6) { out.write(0) }       // AN/NS/AR
        for (label in host.trimEnd('.').split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            require(b.size in 1..63) { "bad label in $host" }
            out.write(b.size)
            out.write(b)
        }
        out.write(0)
        out.write(0); out.write(1) // QTYPE A
        out.write(0); out.write(1) // QCLASS IN
        return out.toByteArray()
    }

    /** Extracts IPv4 addresses from the answer section of a DNS response. */
    internal fun parseAnswer(msg: ByteArray): List<ByteArray> {
        if (msg.size < 12) return emptyList()
        val rcode = msg[3].toInt() and 0x0F
        if (rcode != 0) return emptyList()
        val qd = u16(msg, 4)
        val an = u16(msg, 6)
        var p = 12
        repeat(qd) {
            p = skipName(msg, p)
            p += 4
        }
        val out = ArrayList<ByteArray>()
        repeat(an) {
            if (p >= msg.size) return out
            p = skipName(msg, p)
            if (p + 10 > msg.size) return out
            val type = u16(msg, p)
            val cls = u16(msg, p + 2)
            val rdlen = u16(msg, p + 8)
            p += 10
            if (p + rdlen > msg.size) return out
            if (type == 1 && cls == 1 && rdlen == 4) out.add(msg.copyOfRange(p, p + 4))
            p += rdlen
        }
        return out
    }

    private fun skipName(msg: ByteArray, start: Int): Int {
        var p = start
        while (p < msg.size) {
            val len = msg[p].toInt() and 0xFF
            if (len == 0) return p + 1
            if (len and 0xC0 == 0xC0) return p + 2
            p += 1 + len
        }
        return p
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    internal fun base64Url(data: ByteArray): String =
        Crypto.base64(data).trimEnd('=').replace('+', '-').replace('/', '_')
}
