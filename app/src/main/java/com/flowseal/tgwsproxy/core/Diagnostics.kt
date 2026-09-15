package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.Tls
import com.flowseal.tgwsproxy.net.WsHandshakeError
import java.net.SocketTimeoutException

/**
 * One-shot connection diagnostics: probes each configured DC over TCP and
 * WebSocket (direct, then fronted) and the CF fallback, then suggests what to
 * enable. Runs on a background thread; see MainActivity for the UI.
 */
object Diagnostics {

    private const val TCP_TIMEOUT_MS = 3_000
    private const val WS_TIMEOUT_MS = 4_000
    private const val FRONT_TIMEOUT_MS = 5_000

    class Check(val name: String, val ok: Boolean, val detail: String) {
        override fun toString(): String =
            "${if (ok) "OK  " else "FAIL"}  $name — $detail"
    }

    class Report(val checks: List<Check>, val recommendation: String) {
        fun text(): String = (checks.map { it.toString() } + listOf("→ $recommendation"))
            .joinToString("\n")
    }

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
        var cfOk = false

        val dcs = cfg.dcRedirects.toSortedMap()
        if (dcs.isEmpty()) {
            checks.add(Check("DC list", false, "no DC IPs configured"))
        }
        for ((dc, ip) in dcs) {
            val t0 = System.nanoTime()
            try {
                Tls.connectPlain(ip, 443, TCP_TIMEOUT_MS, 32 * 1024).close()
                val ms = (System.nanoTime() - t0) / 1_000_000
                tcpOk = true
                checks.add(Check("DC$dc TCP", true, "$ip:443 reachable in ${ms}ms"))
            } catch (e: Exception) {
                checks.add(Check("DC$dc TCP", false, "$ip:443: ${shortErr(e)}"))
                continue
            }

            for (domain in Const.wsDomains(dc, false)) {
                try {
                    RawWebSocket.connect(
                        host = ip, domain = domain, timeoutMs = WS_TIMEOUT_MS,
                        bufferSize = cfg.bufferSize,
                    ).close()
                    directOk = true
                    checks.add(Check("DC$dc WS", true, "direct handshake via $domain"))
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
                try {
                    RawWebSocket.connect(
                        host = ip, domain = domain, timeoutMs = FRONT_TIMEOUT_MS,
                        sni = cfg.frontingSni.ifBlank { ProxyConfig.DEFAULT_FRONTING_SNI },
                        bufferSize = cfg.bufferSize,
                    ).close()
                    frontedOk = true
                    checks.add(Check("DC$dc fronted", true, "handshake with neutral SNI"))
                } catch (e: Exception) {
                    checks.add(Check("DC$dc fronted", false, shortErr(e)))
                }
            }
        }

        // CF fallback reachability: plain TCP to the first known CF domain.
        val cfDomain = Balancer.getDomainsForDc(dcs.keys.firstOrNull() ?: 2)
            .firstOrNull()?.let { "kws${dcs.keys.firstOrNull() ?: 2}.$it" }
            ?: ProxyConfig.CFPROXY_DEFAULT_DOMAINS.firstOrNull()
        if (cfDomain != null) {
            try {
                Tls.connectPlain(cfDomain, 443, TCP_TIMEOUT_MS, 32 * 1024).close()
                cfOk = true
                checks.add(Check("CF fallback", true, "$cfDomain:443 reachable"))
            } catch (e: Exception) {
                checks.add(Check("CF fallback", false, "$cfDomain: ${shortErr(e)}"))
            }
        }

        val recommendation = buildRecommendation(tcpOk, directOk, frontedOk, cfOk)
        val report = Report(checks, recommendation)
        Logger.i("Diagnostics:\n${report.text()}")
        return report
    }

    /**
     * Pure suggestion logic, kept separate so it is unit-testable without
     * touching the network.
     */
    fun buildRecommendation(tcpOk: Boolean, directOk: Boolean, frontedOk: Boolean, cfOk: Boolean): String =
        when {
            directOk -> "Direct route works — no evasion needed."
            frontedOk -> "Direct is filtered, neutral SNI works — enable fronting-first."
            cfOk -> "Direct is blocked — keep the CF fallback on, or add your own CF domains."
            tcpOk -> "TCP connects but TLS fails — enable the TLS split and a split delay."
            else -> "Nothing reachable — check the network, VPN or lockdown mode."
        }

    private fun shortErr(e: Exception): String = when (e) {
        is SocketTimeoutException -> "timed out"
        else -> (e.message ?: e.javaClass.simpleName).take(90)
    }
}
