package com.flowseal.tgwsproxy.core

/**
 * Port of proxy/config.py — runtime proxy configuration.
 *
 * Mutated only between proxy restarts; the running engine reads a snapshot.
 */
class ProxyConfig {
    var port: Int = 1443
    var host: String = "127.0.0.1"
    var secret: String = Crypto.randomHex(16)
    /** May be empty (upstream `--dc-ip` with no value): every DC goes through fallbacks. */
    var dcRedirects: Map<Int, String> = mapOf(
        2 to "149.154.167.220",
        4 to "149.154.167.220",
    )
    var bufferSize: Int = 256 * 1024
    var poolSize: Int = 4
    var fallbackCfproxy: Boolean = true
    var cfproxyUserDomains: List<String> = emptyList()
    var cfproxyWorkerDomains: List<String> = emptyList()
    var fakeTlsDomain: String = ""
    var proxyProtocol: Boolean = false
    var forceTestDc: Boolean = false

    /** Split the upstream TLS ClientHello across two TCP segments. */
    var fragmentClientHello: Boolean = true

    /** Pause between the two ClientHello segments, ms (0 = no pause). */
    var fragmentDelayMs: Int = 0

    /** Present a neutral SNI on the first attempt instead of after a timeout. */
    var frontingFirst: Boolean = false

    /** SNI used when fronting; must be a host that is not filtered. */
    var frontingSni: String = DEFAULT_FRONTING_SNI

    /** Keep upstream sockets outside an active VPN tunnel. */
    var bypassVpn: Boolean = true

    /**
     * On mobile data, force the evasion pair (TLS split + fronting-first) for
     * the session even when the base settings have them off.
     */
    var mobileEvasion: Boolean = true

    /** Upstream `disable_secure` (--no-secure): ws:// on port 80 for CF proxy/worker. */
    var disableSecure: Boolean = false

    /** Upstream 1.10.4 verifies upstream TLS certificates; off for old devices. */
    var verifyTls: Boolean = true

    /** Self-hosted relays (whitelist bypass), see [RelayEndpoint]. */
    var relays: List<String> = emptyList()

    /** Try relays before everything else and keep them warm for every DC. */
    var relayFirst: Boolean = false

    /** Worker domains and relays combined into one ordered endpoint list. */
    fun relayEndpoints(): List<RelayEndpoint> =
        RelayEndpoint.parseList(relays, defaultSecure = true) +
            RelayEndpoint.parseList(cfproxyWorkerDomains, defaultSecure = !disableSecure)

    fun copy(): ProxyConfig {
        val c = ProxyConfig()
        c.port = port
        c.host = host
        c.secret = secret
        c.dcRedirects = LinkedHashMap(dcRedirects)
        c.bufferSize = bufferSize
        c.poolSize = poolSize
        c.fallbackCfproxy = fallbackCfproxy
        c.cfproxyUserDomains = cfproxyUserDomains.toList()
        c.cfproxyWorkerDomains = cfproxyWorkerDomains.toList()
        c.fakeTlsDomain = fakeTlsDomain
        c.proxyProtocol = proxyProtocol
        c.forceTestDc = forceTestDc
        c.fragmentClientHello = fragmentClientHello
        c.fragmentDelayMs = fragmentDelayMs
        c.frontingFirst = frontingFirst
        c.frontingSni = frontingSni
        c.bypassVpn = bypassVpn
        c.mobileEvasion = mobileEvasion
        c.disableSecure = disableSecure
        c.verifyTls = verifyTls
        c.relays = relays.toList()
        c.relayFirst = relayFirst
        return c
    }

    /**
     * Applies the mobile-data profile. Pure decision logic, kept here so it is
     * unit-testable without Android APIs. Returns true when overrides fired.
     */
    fun applyMobileProfile(isCellular: Boolean): Boolean {
        if (!mobileEvasion || !isCellular) return false
        var changed = false
        if (!fragmentClientHello) {
            fragmentClientHello = true
            changed = true
        }
        if (!frontingFirst) {
            frontingFirst = true
            changed = true
        }
        return changed
    }

    companion object {
        /** Neutral host used for domain fronting; unfiltered on most networks. */
        const val DEFAULT_FRONTING_SNI = "sprinthost.ru"

        const val CFPROXY_DOMAINS_URL =
            "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

        private const val CFPROXY_MIN_VALID_DOMAINS = 3

        private val CFPROXY_ENC = listOf(
            "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com",
            "twdmbzcm.com", "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com",
            "bxaxtxmrw.com", "dmohrsgmohcrwb.com", "vwbmtmoi.com", "khgrre.com",
            "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com", "orgcnunpj.com",
            "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
        )

        private val SUFFIX = intArrayOf(46, 99, 111, 46, 117, 107)
            .map { it.toChar() }.joinToString("")

        /** Only for decoding CF proxy domains (mirror of config.py::_dd). */
        fun decodeDomain(s: String): String {
            if (!s.endsWith(".com")) return s
            val p = s.substring(0, s.length - 4)
            val n = p.count { it.isLetter() }
            val sb = StringBuilder(p.length)
            for (c in p) {
                if (c.isLetter()) {
                    val base = if (c > '`') 'a'.code else 'A'.code
                    var v = (c.code - base - n) % 26
                    if (v < 0) v += 26
                    sb.append((v + base).toChar())
                } else {
                    sb.append(c)
                }
            }
            return sb.toString() + SUFFIX
        }

        val CFPROXY_DEFAULT_DOMAINS: List<String> = CFPROXY_ENC.map { decodeDomain(it) }

        fun coerceDomainList(value: Any?): List<String> {
            val items: List<String> = when (value) {
                is String -> value.replace(',', ' ').replace(';', ' ').split(" ")
                is Collection<*> -> value.filterIsInstance<String>()
                    .flatMap { it.replace(',', ' ').replace(';', ' ').split(" ") }
                else -> return emptyList()
            }
            val seen = HashSet<String>()
            val result = ArrayList<String>()
            for (raw in items) {
                val item = raw.trim()
                if (item.isEmpty()) continue
                if (!seen.add(item.lowercase())) continue
                result.add(item)
            }
            return result
        }

        fun isValidDomain(domain: String): Boolean {
            if (domain.isEmpty() || domain.length > 253) return false
            if (domain.startsWith(".") || domain.endsWith(".")) return false
            val labels = domain.split(".")
            if (labels.size < 2) return false
            for (label in labels) {
                if (label.isEmpty() || label.length > 63) return false
                if (label.first() == '-' || label.last() == '-') return false
                if (!label.all { it.isLetterOrDigit() || it == '-' }) return false
            }
            val tld = labels.last()
            if (tld.length < 2 || tld.none { it.isLetter() }) return false
            return true
        }

        fun normalizeDomainPool(domains: List<String>): List<String> {
            val seen = HashSet<String>()
            val out = ArrayList<String>()
            for (d in domains) {
                val item = d.trim().lowercase()
                if (!isValidDomain(item)) continue
                if (!seen.add(item)) continue
                out.add(item)
            }
            return out
        }

        fun minValidDomains(): Int = CFPROXY_MIN_VALID_DOMAINS

        /** Parses "DC:IP" entries, mirror of config.py::parse_dc_ip_list. */
        fun parseDcIpList(entries: List<String>): Map<Int, String> {
            val out = LinkedHashMap<Int, String>()
            for (raw in entries) {
                val entry = raw.trim()
                if (entry.isEmpty()) continue
                val idx = entry.indexOf(':')
                if (idx < 0) throw IllegalArgumentException("Invalid dc-ip format '$entry', expected DC:IP")
                val dcS = entry.substring(0, idx)
                val ipS = entry.substring(idx + 1)
                val dc = dcS.trim().toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid dc-ip '$entry'")
                if (!isIpv4(ipS.trim())) throw IllegalArgumentException("Invalid dc-ip '$entry'")
                out[dc] = ipS.trim()
            }
            return out
        }

        fun isIpv4(s: String): Boolean {
            val parts = s.split(".")
            if (parts.size != 4) return false
            for (p in parts) {
                if (p.isEmpty() || p.length > 3) return false
                if (!p.all { it.isDigit() }) return false
                val v = p.toInt()
                if (v < 0 || v > 255) return false
            }
            return true
        }
    }
}
