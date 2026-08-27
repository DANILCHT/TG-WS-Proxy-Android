package com.flowseal.tgwsproxy.core

import java.io.ByteArrayOutputStream
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Port of config.py::refresh_cfproxy_domains + start_cfproxy_domain_refresh.
 *
 * Fetches the CF-proxied domain pool from GitHub every hour. The request is
 * IP-pinned like in the Python version, because DNS for
 * raw.githubusercontent.com is frequently poisoned in the networks this app
 * targets. Certificate and hostname validation stay enabled and are performed
 * against the real hostname, so pinning does not weaken TLS.
 */
class CfDomainRefresher(private val config: ProxyConfig) {

    private companion object {
        val GITHUB_IPS = mapOf(
            "release-assets.githubusercontent.com" to "185.199.109.133",
            "raw.githubusercontent.com" to "185.199.109.133",
        )
        const val REFRESH_INTERVAL_MS = 3_600_000L
        const val MAX_BODY = 256 * 1024
    }

    @Volatile
    private var thread: Thread? = null

    @Volatile
    private var running = false

    fun start() {
        stop()
        Balancer.updateDomainsList(ProxyConfig.CFPROXY_DEFAULT_DOMAINS)
        running = true
        val t = Thread({
            try {
                while (running) {
                    runCatching { refresh() }
                    var waited = 0L
                    while (running && waited < REFRESH_INTERVAL_MS) {
                        Thread.sleep(1_000)
                        waited += 1_000
                    }
                }
            } catch (_: InterruptedException) {
            }
        }, "cfproxy-domains-refresh")
        t.isDaemon = true
        thread = t
        t.start()
    }

    fun stop() {
        running = false
        thread?.interrupt()
        thread = null
    }

    private fun refresh() {
        if (config.cfproxyUserDomains.isNotEmpty()) return

        val fetched = fetchDomainList()
        val pool = ProxyConfig.normalizeDomainPool(fetched)
        if (pool.size >= ProxyConfig.minValidDomains()) {
            Balancer.updateDomainsList(pool)
            Logger.i("CF proxy domain pool updated from GitHub (${pool.size} domains)")
            return
        }

        if (fetched.isNotEmpty()) {
            Logger.w(
                "Ignoring fetched CF proxy domains due to low-quality payload " +
                    "(total=${fetched.size}, valid=${pool.size}, " +
                    "required>=${ProxyConfig.minValidDomains()}); keeping current domain pool"
            )
        } else {
            Logger.w(
                "CF proxy domain refresh failed or empty response; keeping current domain pool"
            )
        }
    }

    private fun fetchDomainList(): List<String> {
        val cacheBuster = (1..7).map { 'a' + Crypto.randomInt(26) }.joinToString("")
        val urlStr = "${ProxyConfig.CFPROXY_DOMAINS_URL}?$cacheBuster"
        val url = URL(urlStr)
        val pinnedIp = GITHUB_IPS[url.host]

        val body = try {
            if (pinnedIp != null) {
                fetchPinned(url, pinnedIp)
            } else {
                fetchPlain(url)
            }
        } catch (e: Exception) {
            Logger.w("Failed to fetch CF proxy domain list: $e")
            return emptyList()
        }

        return body.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { ProxyConfig.decodeDomain(it) }
            .toList()
    }

    private fun fetchPlain(url: URL): String {
        val conn = NetworkBinder.openConnection(url) as HttpsURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000
        conn.setRequestProperty("User-Agent", "tg-ws-proxy")
        try {
            return conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Manual HTTPS GET over a socket connected to [pinnedIp] while presenting
     * the real hostname for SNI, certificate validation and the Host header.
     */
    private fun fetchPinned(url: URL, pinnedIp: String): String {
        val host = url.host
        val raw = NetworkBinder.connect(pinnedIp, 443, 10_000) {
            Socket().also { runCatching { it.tcpNoDelay = true } }
        }
        raw.soTimeout = 10_000

        val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
            .createSocket(raw, host, 443, true) as SSLSocket
        try {
            if (android.os.Build.VERSION.SDK_INT >= 24) {
                runCatching {
                    val params = ssl.sslParameters
                    params.serverNames = listOf(SNIHostName(host))
                    ssl.sslParameters = params
                }
            }
            ssl.soTimeout = 10_000
            ssl.startHandshake()

            val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
            if (!verifier.verify(host, ssl.session)) {
                throw javax.net.ssl.SSLPeerUnverifiedException(
                    "certificate hostname mismatch for $host"
                )
            }

            val path = url.file.ifEmpty { "/" }
            val req = "GET $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: tg-ws-proxy\r\n" +
                "Accept: */*\r\n" +
                "Connection: close\r\n\r\n"
            ssl.outputStream.write(req.toByteArray(Charsets.ISO_8859_1))
            ssl.outputStream.flush()

            val all = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            val input = ssl.inputStream
            while (all.size() < MAX_BODY) {
                val n = input.read(buf)
                if (n <= 0) break
                all.write(buf, 0, n)
            }

            val text = String(all.toByteArray(), Charsets.UTF_8)
            val sep = text.indexOf("\r\n\r\n")
            if (sep < 0) throw java.io.IOException("malformed HTTP response")

            val statusLine = text.substringBefore("\r\n")
            val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0
            if (status != 200) throw java.io.IOException("HTTP $status for $host")

            val headerBlock = text.substring(0, sep)
            var payload = text.substring(sep + 4)
            if (headerBlock.contains("Transfer-Encoding: chunked", ignoreCase = true)) {
                payload = dechunk(payload)
            }
            return payload
        } finally {
            runCatching { ssl.close() }
            runCatching { raw.close() }
        }
    }

    private fun dechunk(body: String): String {
        val out = StringBuilder()
        var i = 0
        while (i < body.length) {
            val eol = body.indexOf("\r\n", i)
            if (eol < 0) break
            val size = body.substring(i, eol).trim().substringBefore(';').toIntOrNull(16) ?: break
            if (size == 0) break
            val start = eol + 2
            val end = minOf(start + size, body.length)
            out.append(body, start, end)
            i = end + 2
        }
        return out.toString()
    }
}
