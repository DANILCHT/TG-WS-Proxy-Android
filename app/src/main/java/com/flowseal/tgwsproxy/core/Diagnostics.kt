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
 * WebSocket (direct, then fronted), the relays and Workers, the Cloudflare
 * fallback over both TLS and plain HTTP, and whether the network only lets
 * "whitelisted" destinations through. Every WebSocket check goes all the way
 * to a Telegram answer ([MtprotoProbe]). Then suggests what to change. Runs on
 * a background thread; see MainActivity for the UI.
 */
object Diagnostics {

    private const val TCP_TIMEOUT_MS = 3_000
    private const val WS_TIMEOUT_MS = 6_000
    private const val FRONT_TIMEOUT_MS = 6_000
    private const val MAX_RELAYS = 6

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
        val cfHttpOk: Boolean = false,
        val cfTlsOk: Boolean = false,
    )

    fun run(cfg: ProxyConfig, russian: Boolean = false): Report {
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

            val domain = Const.wsDomains(dc, false).first()
            val t1 = System.nanoTime()
            val direct = probeWs("direct via $domain", dc) {
                RawWebSocket.connect(
                    host = ip, domain = domain, timeoutMs = WS_TIMEOUT_MS,
                    bufferSize = cfg.bufferSize,
                )
            }
            directOk = directOk || direct.ok
            checks.add(Check("DC$dc WS", direct.ok, if (direct.ok) "${direct.detail} in ${ms(t1)}ms" else direct.detail))

            if (!direct.ok) {
                val t2 = System.nanoTime()
                val fronted = probeWs("neutral SNI", dc) {
                    RawWebSocket.connect(
                        host = ip, domain = domain, timeoutMs = FRONT_TIMEOUT_MS,
                        sni = cfg.frontingSni.ifBlank { ProxyConfig.DEFAULT_FRONTING_SNI },
                        bufferSize = cfg.bufferSize,
                    )
                }
                frontedOk = frontedOk || fronted.ok
                checks.add(Check("DC$dc fronted", fronted.ok, if (fronted.ok) "${fronted.detail} in ${ms(t2)}ms" else fronted.detail))
            }
        }

        val pool = Executors.newFixedThreadPool(4)
        try {
            // Relays and Workers (both variants of a Worker), in parallel.
            val endpoints = cfg.relayEndpoints().take(MAX_RELAYS)
            val probeDc = 2
            val dst = Const.DC_DEFAULT_IPS[probeDc]!!
            val relayFutures = endpoints.map { ep ->
                ep to pool.submit(Callable {
                    val t0 = System.nanoTime()
                    probeWs(ep.toString(), probeDc) {
                        ep.connect(dst, probeDc, WS_TIMEOUT_MS, cfg.bufferSize)
                    }.let { if (it.ok) Probe(true, "$ep in ${ms(t0)}ms") else it }
                })
            }
            for ((_, f) in relayFutures) {
                val r = runCatching { f.get(WS_TIMEOUT_MS * 3L, TimeUnit.MILLISECONDS) }
                    .getOrElse { Probe(false, "timed out") }
                relayOk = relayOk || r.ok
                checks.add(Check("Relay", r.ok, r.detail))
            }

            // Cloudflare proxy: plain HTTP and TLS side by side, on up to two domains.
            var cfHttpOk = false
            var cfTlsOk = false
            if (cfg.fallbackCfproxy) {
                val firstDc = dcs.keys.firstOrNull() ?: 2
                val bases = (cfg.cfproxyUserDomains.ifEmpty { Balancer.getDomainsForDc(firstDc) })
                    .ifEmpty { ProxyConfig.CFPROXY_DEFAULT_DOMAINS.shuffled() }
                    .take(2)
                val modes = if (cfg.disableSecure) listOf(false) else listOf(false, true)
                for (base in bases) {
                    val host = "kws$firstDc.$base"
                    val futures = modes.map { tls ->
                        tls to pool.submit(Callable {
                            val t0 = System.nanoTime()
                            probeWs(host, firstDc) {
                                RawWebSocket.connect(
                                    host = host, domain = host, timeoutMs = WS_TIMEOUT_MS,
                                    bufferSize = cfg.bufferSize, secure = tls,
                                )
                            }.let { if (it.ok) Probe(true, "Telegram answered via $host in ${ms(t0)}ms") else it }
                        })
                    }
                    for ((tls, f) in futures) {
                        val r = runCatching { f.get(WS_TIMEOUT_MS * 3L, TimeUnit.MILLISECONDS) }
                            .getOrElse { Probe(false, "$host: timed out") }
                        if (tls) cfTlsOk = cfTlsOk || r.ok else cfHttpOk = cfHttpOk || r.ok
                        checks.add(Check(if (tls) "CF TLS:443" else "CF HTTP:80", r.ok, r.detail))
                    }
                    if (cfHttpOk || cfTlsOk) break
                }
            }

            var whitelist = false
            if (!directOk && !frontedOk && !cfHttpOk && !cfTlsOk && !relayOk) {
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
                tcpOk, directOk, frontedOk, endpoints.isNotEmpty(), relayOk,
                cfHttpOk || cfTlsOk, whitelist, cfHttpOk, cfTlsOk,
            )
            val report = Report(checks, buildRecommendation(outcome, russian))
            Logger.i("Diagnostics:\n${report.text()}")
            return report
        } finally {
            pool.shutdownNow()
        }
    }

    private class Probe(val ok: Boolean, val detail: String)

    /** Opens a WebSocket with [open] and asks Telegram for a resPQ through it. */
    private fun probeWs(what: String, dc: Int, open: () -> RawWebSocket): Probe {
        val ws = try {
            open()
        } catch (e: WsHandshakeError) {
            val hint = when {
                e.isRedirect -> " (redirects to ${e.location})"
                e.statusCode == 401 || e.statusCode == 403 -> " (wrong key or blocked)"
                e.statusCode == 404 -> " (wrong path?)"
                e.statusCode == 429 -> " (daily limit)"
                else -> ""
            }
            return Probe(false, "$what: ${e.statusLine}$hint")
        } catch (e: Exception) {
            return Probe(false, "$what: ${shortErr(e)}")
        }
        return try {
            val err = MtprotoProbe.check(ws, dc, WS_TIMEOUT_MS)
            if (err == null) Probe(true, what) else Probe(false, "$what: connected, but $err")
        } catch (e: Exception) {
            Probe(false, "$what: connected, but Telegram did not answer (${shortErr(e)})")
        } finally {
            ws.abort()
        }
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
    fun buildRecommendation(o: Outcome, russian: Boolean = false): String {
        fun t(en: String, ru: String) = if (russian) ru else en
        return when {
            o.directOk -> t(
                "Direct route works — no evasion needed.",
                "Прямой маршрут работает — обход не нужен.",
            )
            o.relayOk && o.whitelistSuspected -> t(
                "Whitelist mode — your relay works; enable \"Relay first\".",
                "Режим белых списков — ваш relay работает; включите «Relay в приоритете».",
            )
            o.relayOk -> t(
                "Direct is blocked, your relay works — enable \"Relay first\" for the lowest ping.",
                "Прямой путь закрыт, ваш relay работает — включите «Relay в приоритете» для меньшего пинга.",
            )
            o.frontedOk -> t(
                "Direct is filtered, neutral SNI works — enable fronting-first.",
                "Прямой путь фильтруется, нейтральный SNI проходит — включите «Сразу подставлять нейтральный домен».",
            )
            o.cfHttpOk && !o.cfTlsOk -> t(
                "Direct is blocked and TLS to Cloudflare is filtered, but plain HTTP (port 80) works — the proxy switches to it automatically.",
                "Прямой путь закрыт и TLS к Cloudflare режется, но обычный HTTP (порт 80) проходит — прокси сам переключается на него.",
            )
            o.cfTlsOk && !o.cfHttpOk -> t(
                "Direct is blocked, Cloudflare works over TLS (port 80 is closed) — used automatically.",
                "Прямой путь закрыт, Cloudflare работает по TLS (порт 80 закрыт) — используется автоматически.",
            )
            o.cfOk -> t(
                "Direct is blocked — the Cloudflare (CF) fallback works.",
                "Прямой путь закрыт — резерв через Cloudflare (CF) работает.",
            )
            o.whitelistSuspected && o.relayConfigured -> t(
                "Whitelist mode and the relay is unreachable — host it in a network your operator allows.",
                "Режим белых списков, а relay недоступен — разместите его в сети, которую пропускает оператор.",
            )
            o.whitelistSuspected -> t(
                "Whitelist mode: Telegram and Cloudflare are cut off. Only a relay on an allowed network helps — see \"Whitelist bypass\".",
                "Режим белых списков: Telegram и Cloudflare отрезаны. Поможет только relay в разрешённой сети — см. «Обход белых списков».",
            )
            o.tcpOk -> t(
                "TCP connects but TLS fails — enable the TLS split and a split delay.",
                "TCP подключается, но TLS не проходит — включите разрез TLS-рукопожатия и паузу между частями.",
            )
            else -> t(
                "Nothing reachable — check the network, VPN or lockdown mode.",
                "Ничего не доступно — проверьте сеть, VPN или режим блокировки без VPN.",
            )
        }
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
