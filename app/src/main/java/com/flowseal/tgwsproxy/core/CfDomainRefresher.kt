package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.HttpLite

/**
 * Port of config.py::refresh_cfproxy_domains + start_cfproxy_domain_refresh.
 *
 * Fetches the CF-proxied domain pool from GitHub every hour. DNS for
 * raw.githubusercontent.com is frequently poisoned in the networks this app
 * targets, so [HttpLite] falls back to DoH and pinned GitHub IPs, like the
 * Python version. Certificate and hostname validation stay enabled against the
 * real hostname, so pinning does not weaken TLS.
 */
class CfDomainRefresher(private val config: ProxyConfig) {

    private companion object {
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
        val body = try {
            val resp = HttpLite.request(
                HttpLite.Request(
                    url = "${ProxyConfig.CFPROXY_DOMAINS_URL}?$cacheBuster",
                    timeoutMs = 10_000,
                    maxBytes = MAX_BODY,
                )
            )
            if (resp.status != 200) throw java.io.IOException("HTTP ${resp.status}")
            resp.text()
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
}
