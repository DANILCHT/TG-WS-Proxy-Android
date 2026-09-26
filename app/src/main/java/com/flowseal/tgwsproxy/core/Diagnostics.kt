package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.Tls
import com.flowseal.tgwsproxy.net.WsHandshakeError
import java.net.SocketTimeoutException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * One-shot connection diagnostics: probes each configured DC over TCP and
 * WebSocket (direct, then fronted), the relays, the CF fallback, and whether
 * the network only lets "whitelisted" destinations through. Then suggests
 * what to change. Runs on a background thread; see MainActivity for the UI.
 */
object Diagnostics {

    private const val TCP_TIMEOUT_MS = 3_000
    private const val WS_TIMEOUT_MS = 5_000
    private const val FRONT_TIMEOUT_MS = 5_000

    /**
     * Russian services that stay reachable when a mobile operator switches to
     * whitelist-only mode, and foreign ones that do not. Only TCP connects are
     * made; nothing is sent.
     */
    private val WHITELISTED_PROBES = listOf("ya.ru", "vk.com", "gosuslugi.ru")
    private val CONTROL_PROBES = listOf("1.1.1.1", "github.com", "8.8.8.8")

    class Check(val name: String, val ok: Boolean, val detail: String) {
        override fun toString(): String =
            "${if (ok) "OK  " else "FAIL"}  $name — $detail"
    }

    class Report(val checks: List<Check>, val recommendation: String) {
        fun text(): String = (checks.map { it.toString() } + listOf("→ $recommendation"))
            .joinToString("\n")
    }

    class Outcome(
        val tcpOk: Boolean,
        val directOk: Boolean,
        val frontedOk: Boolean,
        val relayConfigured: Boolean,
        val relayOk: Boolean,
        val cfOk: Boolean,
        /** Only well-known Russian services answer: whitelist mode. */
        val whitelistSuspected: Boolean,
    )

    fun run(cfg: ProxyConfig): Report {
        val checks = ArrayList<Check>()
        checks.add(
            Check(
                "Network",
                true,
                "${NetworkBinder.activeTransport()}, VPN bypass: ${NetworkBinder.describe()}",
            )
        )

        var tcpOk = false
        var directOk = false
        var frontedOk = false
        var relayOk = false
        var cfOk = false

        val dcs = cfg.dcRedirects.toSortedMap()
        if (dcs.isEmpty()) {
            checks.add(Check("DC list", true, "empty — every DC goes through fallbacks"))
        }
        for ((dc, ip) in dcs) {
            val t0 = System.nanoTime()
            try {
                Tls.connectPlain(ip, 443, TCP_TIMEOUT_MS, 32 * 1024).close()
                tcpOk = true
                checks.add(Check("DC$dc TCP", true, "$ip:443 in ${ms(t0)}ms"))
            } catch (e: Exception) {
                checks.add(Check("DC$dc TCP", false, "$ip:443: ${shortErr(e)}"))
                continue
            }

            for (domain in Const.wsDomains(dc, false)) {
                val t1 = System.nanoTime()
                try {
                    RawWebSocket.connect(
                        host = ip, domain = domain, timeoutMs = WS_TIMEOUT_MS,
                        bufferSize = cfg.bufferSize,
                    ).close()
                    directOk = true
                    checks.add(Check("DC$dc WS", true, "direct via $domain in ${ms(t1)}ms"))
                    break
                } catch (e: WsHandshakeError) {
                    if (e.isRedirect) {
                        checks.add(Check("DC$dc WS", false, "$domain redirects to ${e.location}"))
                        continue
                    }
                    checks.add(Check("DC$dc WS", false, "$domain: ${e.statusLine}"))
                    break
                } catch (e: Exception) {
                    checks.add(Check("DC$dc WS", false, "$domain: ${shortErr(e)}"))
                    break
                }
            }

            if (!directOk) {
                val domain = Const.wsDomains(dc, false).first()
                val t2 = System.nanoTime()
                try {
                    RawWebSocket.connect(
                        host = ip, domain = domain, timeoutMs = FRONT_TIMEOUT_MS,
                        sni = cfg.frontingSni.ifBlank { ProxyConfig.DEFAULT_FRONTING_SNI },
                        bufferSize = cfg.bufferSize,
                    ).close()
                    frontedOk = true
                    checks.add(Check("DC$dc fronted", true, "neutral SNI in ${ms(t2)}ms"))
                } catch (e: Exception) {
                    checks.add(Check("DC$dc fronted", false, shortErr(e)))
                }
            }
        }

        val endpoints = cfg.relayEndpoints()
        val probeDc = 2
        val dst = Const.DC_DEFAULT_IPS[probeDc]!!
        for (ep in endpoints.take(5)) {
            val t0 = System.nanoTime()
            try {
                ep.connect(dst, probeDc, WS_TIMEOUT_MS, cfg.bufferSize).close()
                relayOk = true
                checks.add(Check("Relay", true, "$ep in ${ms(t0)}ms"))
            } catch (e: WsHandshakeError) {
                val hint = when (e.statusCode) {
                    401, 403 -> " (wrong key?)"
                    404 -> " (wrong path?)"
                    429 -> " (daily limit)"
                    else -> ""
                }
                checks.add(Check("Relay", false, "$ep: ${e.statusLine}$hint"))
            } catch (e: Exception) {
                checks.add(Check("Relay", false, "$ep: ${shortErr(e)}"))
            }
        }

        // CF fallback reachability: plain TCP to the first known CF domain.
        val firstDc = dcs.keys.firstOrNull() ?: 2
        val cfDomain = Balancer.getDomainsForDc(firstDc).firstOrNull()?.let { "kws$firstDc.$it" }
            ?: ProxyConfig.CFPROXY_DEFAULT_DOMAINS.firstOrNull()?.let { "kws$firstDc.$it" }
        if (cfg.fallbackCfproxy && cfDomain != null) {
            val t0 = System.nanoTime()
            try {
                RawWebSocket.connect(
                    host = cfDomain, domain = cfDomain, timeoutMs = WS_TIMEOUT_MS,
                    bufferSize = cfg.bufferSize, secure = !cfg.disableSecure,
                ).close()
                cfOk = true
                checks.add(Check("CF fallback", true, "$cfDomain in ${ms(t0)}ms"))
            } catch (e: Exception) {
                checks.add(Check("CF fallback", false, "$cfDomain: ${shortErr(e)}"))
            }
        }

        var whitelist = false
        if (!directOk && !frontedOk && !cfOk && !relayOk) {
            val allowed = probeAny(WHITELISTED_PROBES)
            val control = probeAny(CONTROL_PROBES)
            whitelist = allowed != null && control == null
            checks.add(
                Check(
                    "Whitelist test",
                    !whitelist,
                    when {
                        whitelist -> "only Russian services reachable ($allowed) — whitelist mode"
                        allowed == null && control == null -> "nothing reachable at all"
                        else -> "foreign hosts reachable (${control ?: "-"})"
                    },
                )
            )
        }

        val outcome = Outcome(
            tcpOk, directOk, frontedOk, endpoints.isNotEmpty(), relayOk, cfOk, whitelist,
        )
        val report = Report(checks, buildRecommendation(outcome))
        Logger.i("Diagnostics:\n${report.text()}")
        return report
    }

    /** Returns the first host from [hosts] that accepts a TCP connection on 443. */
    private fun probeAny(hosts: List<String>): String? {
        val pool = Executors.newFixedThreadPool(hosts.size)
        try {
            val futures = hosts.map { h ->
                h to pool.submit(Callable {
                    Tls.connectPlain(h, 443, TCP_TIMEOUT_MS, 16 * 1024).close()
                    true
                })
            }
            for ((h, f) in futures) {
                if (runCatching { f.get(TCP_TIMEOUT_MS + 2_000L, TimeUnit.MILLISECONDS) }.getOrDefault(false)) {
                    return h
                }
            }
            return null
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * Pure suggestion logic, kept separate so it is unit-testable without
     * touching the network.
     */
    fun buildRecommendation(o: Outcome): String = when {
        o.directOk -> "Direct route works — no evasion needed."
        o.relayOk && o.whitelistSuspected -> "Whitelist mode — your relay works; enable \"Relay first\"."
        o.relayOk -> "Direct is blocked, your relay works — enable \"Relay first\" for the lowest ping."
        o.frontedOk -> "Direct is filtered, neutral SNI works — enable fronting-first."
        o.cfOk -> "Direct is blocked — keep the CF fallback on, or add your own relay."
        o.whitelistSuspected && o.relayConfigured ->
            "Whitelist mode and the relay is unreachable — host it in a network your operator allows."
        o.whitelistSuspected ->
            "Whitelist mode: Telegram and Cloudflare are cut off. Only a relay on an allowed network helps — see \"Whitelist bypass\"."
        o.tcpOk -> "TCP connects but TLS fails — enable the TLS split and a split delay."
        else -> "Nothing reachable — check the network, VPN or lockdown mode."
    }

    /** Old signature, kept for callers that only know the basic checks. */
    fun buildRecommendation(tcpOk: Boolean, directOk: Boolean, frontedOk: Boolean, cfOk: Boolean): String =
        buildRecommendation(Outcome(tcpOk, directOk, frontedOk, false, false, cfOk, false))

    private fun ms(t0: Long) = (System.nanoTime() - t0) / 1_000_000

    private fun shortErr(e: Exception): String = when (e) {
        is SocketTimeoutException -> "timed out"
        else -> (e.message ?: e.javaClass.simpleName).take(90)
    }
}
