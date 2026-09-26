package com.flowseal.tgwsproxy.core

import android.content.Context
import android.content.SharedPreferences

/**
 * Persistent settings, port of utils/default_config.py plus the tray config
 * form fields that make sense on Android.
 */
class Settings private constructor(private val prefs: SharedPreferences) {

    companion object {
        private const val FILE = "tgwsproxy"

        const val KEY_PORT = "port"
        const val KEY_HOST = "host"
        const val KEY_SECRET = "secret"
        const val KEY_DC_IP = "dc_ip"
        const val KEY_VERBOSE = "verbose"
        const val KEY_BUF_KB = "buf_kb"
        const val KEY_POOL_SIZE = "pool_size"
        const val KEY_CFPROXY = "cfproxy"
        const val KEY_CF_USER_ENABLED = "cfproxy_user_domain_enabled"
        const val KEY_CF_USER_DOMAIN = "cfproxy_user_domain"
        const val KEY_CF_WORKER_ENABLED = "cfproxy_worker_enabled"
        const val KEY_CF_WORKER_DOMAIN = "cfproxy_worker_domain"
        const val KEY_FAKE_TLS_DOMAIN = "fake_tls_domain"
        const val KEY_FORCE_TEST_DC = "force_test_dc"
        const val KEY_AUTOSTART = "autostart"
        const val KEY_FIRST_RUN_DONE = "first_run_done"
        const val KEY_TLS_SPLIT = "tls_split"
        const val KEY_TLS_SPLIT_DELAY = "tls_split_delay_ms"
        const val KEY_FRONTING_FIRST = "fronting_first"
        const val KEY_FRONTING_SNI = "fronting_sni"
        const val KEY_BYPASS_VPN = "bypass_vpn"
        const val KEY_MOBILE_EVASION = "mobile_evasion"
        const val KEY_QUIET_NOTIFICATION = "quiet_notification"
        const val KEY_AUTO_UPDATE_CHECK = "auto_update_check"
        const val KEY_UPDATE_SKIPPED = "update_skipped_version"
        const val KEY_UPDATE_LAST_CHECK = "update_last_check"
        const val KEY_AUTO_INSTALL_UPDATES = "auto_install_updates"
        const val KEY_RELAYS = "relays"
        const val KEY_RELAY_FIRST = "relay_first"
        const val KEY_VERIFY_TLS = "verify_tls"
        const val KEY_NO_SECURE = "no_secure"
        const val KEY_WAS_RUNNING = "was_running"

        const val DEFAULT_PORT = 1443
        const val DEFAULT_HOST = "127.0.0.1"
        val DEFAULT_DC_IP = listOf("2:149.154.167.220", "4:149.154.167.220")
        const val DEFAULT_BUF_KB = 256
        const val DEFAULT_POOL_SIZE = 4
        const val MAX_TLS_SPLIT_DELAY_MS = 500

        @Volatile
        private var instance: Settings? = null

        fun get(context: Context): Settings {
            return instance ?: synchronized(this) {
                instance ?: Settings(
                    context.applicationContext
                        .getSharedPreferences(FILE, Context.MODE_PRIVATE)
                ).also { instance = it }
            }
        }
    }

    var port: Int
        get() = prefs.getInt(KEY_PORT, DEFAULT_PORT)
        set(v) = prefs.edit().putInt(KEY_PORT, v).apply()

    var host: String
        get() = prefs.getString(KEY_HOST, DEFAULT_HOST) ?: DEFAULT_HOST
        set(v) = prefs.edit().putString(KEY_HOST, v).apply()

    /** Generated on first access, like the desktop tray config does. */
    var secret: String
        get() {
            val existing = prefs.getString(KEY_SECRET, null)
            if (existing != null && existing.length == 32) return existing
            val fresh = Crypto.randomHex(16)
            prefs.edit().putString(KEY_SECRET, fresh).apply()
            return fresh
        }
        set(v) = prefs.edit().putString(KEY_SECRET, v).apply()

    /**
     * Unset means the defaults; an explicitly empty list is kept, like
     * upstream's bare `--dc-ip`: every DC then goes through the fallbacks
     * (the documented fix for media not loading on non-Premium accounts).
     */
    var dcIp: List<String>
        get() {
            val raw = prefs.getString(KEY_DC_IP, null) ?: return DEFAULT_DC_IP
            return splitList(raw)
        }
        set(v) = prefs.edit().putString(KEY_DC_IP, v.joinToString(",")).apply()

    var verbose: Boolean
        get() = prefs.getBoolean(KEY_VERBOSE, false)
        set(v) = prefs.edit().putBoolean(KEY_VERBOSE, v).apply()

    var bufKb: Int
        get() = prefs.getInt(KEY_BUF_KB, DEFAULT_BUF_KB)
        set(v) = prefs.edit().putInt(KEY_BUF_KB, v).apply()

    var poolSize: Int
        get() = prefs.getInt(KEY_POOL_SIZE, DEFAULT_POOL_SIZE)
        set(v) = prefs.edit().putInt(KEY_POOL_SIZE, v).apply()

    var cfproxy: Boolean
        get() = prefs.getBoolean(KEY_CFPROXY, true)
        set(v) = prefs.edit().putBoolean(KEY_CFPROXY, v).apply()

    var cfUserDomainEnabled: Boolean
        get() = prefs.getBoolean(KEY_CF_USER_ENABLED, false)
        set(v) = prefs.edit().putBoolean(KEY_CF_USER_ENABLED, v).apply()

    var cfUserDomain: List<String>
        get() = splitList(prefs.getString(KEY_CF_USER_DOMAIN, null))
        set(v) = prefs.edit().putString(KEY_CF_USER_DOMAIN, v.joinToString(",")).apply()

    var cfWorkerEnabled: Boolean
        get() = prefs.getBoolean(KEY_CF_WORKER_ENABLED, false)
        set(v) = prefs.edit().putBoolean(KEY_CF_WORKER_ENABLED, v).apply()

    var cfWorkerDomain: List<String>
        get() = splitList(prefs.getString(KEY_CF_WORKER_DOMAIN, null))
        set(v) = prefs.edit().putString(KEY_CF_WORKER_DOMAIN, v.joinToString(",")).apply()

    var fakeTlsDomain: String
        get() = prefs.getString(KEY_FAKE_TLS_DOMAIN, "")?.trim() ?: ""
        set(v) = prefs.edit().putString(KEY_FAKE_TLS_DOMAIN, v.trim()).apply()

    var forceTestDc: Boolean
        get() = prefs.getBoolean(KEY_FORCE_TEST_DC, false)
        set(v) = prefs.edit().putBoolean(KEY_FORCE_TEST_DC, v).apply()

    var autostart: Boolean
        get() = prefs.getBoolean(KEY_AUTOSTART, false)
        set(v) = prefs.edit().putBoolean(KEY_AUTOSTART, v).apply()

    var firstRunDone: Boolean
        get() = prefs.getBoolean(KEY_FIRST_RUN_DONE, false)
        set(v) = prefs.edit().putBoolean(KEY_FIRST_RUN_DONE, v).apply()

    var tlsSplit: Boolean
        get() = prefs.getBoolean(KEY_TLS_SPLIT, true)
        set(v) = prefs.edit().putBoolean(KEY_TLS_SPLIT, v).apply()

    var tlsSplitDelayMs: Int
        get() = prefs.getInt(KEY_TLS_SPLIT_DELAY, 0)
        set(v) = prefs.edit().putInt(KEY_TLS_SPLIT_DELAY, v).apply()

    var frontingFirst: Boolean
        get() = prefs.getBoolean(KEY_FRONTING_FIRST, false)
        set(v) = prefs.edit().putBoolean(KEY_FRONTING_FIRST, v).apply()

    var frontingSni: String
        get() = prefs.getString(KEY_FRONTING_SNI, "")?.trim().orEmpty()
            .ifEmpty { ProxyConfig.DEFAULT_FRONTING_SNI }
        set(v) = prefs.edit().putString(KEY_FRONTING_SNI, v.trim()).apply()

    var bypassVpn: Boolean
        get() = prefs.getBoolean(KEY_BYPASS_VPN, true)
        set(v) = prefs.edit().putBoolean(KEY_BYPASS_VPN, v).apply()

    var mobileEvasion: Boolean
        get() = prefs.getBoolean(KEY_MOBILE_EVASION, true)
        set(v) = prefs.edit().putBoolean(KEY_MOBILE_EVASION, v).apply()

    /**
     * Minimal foreground notification: no counters, no buttons, hidden from the
     * lock screen. A foreground service cannot run with no notification at all.
     */
    var quietNotification: Boolean
        get() = prefs.getBoolean(KEY_QUIET_NOTIFICATION, false)
        set(v) = prefs.edit().putBoolean(KEY_QUIET_NOTIFICATION, v).apply()

    var autoUpdateCheck: Boolean
        get() = prefs.getBoolean(KEY_AUTO_UPDATE_CHECK, true)
        set(v) = prefs.edit().putBoolean(KEY_AUTO_UPDATE_CHECK, v).apply()

    /** Download and install found updates without asking (needs [autoUpdateCheck]). */
    var autoInstallUpdates: Boolean
        get() = prefs.getBoolean(KEY_AUTO_INSTALL_UPDATES, true)
        set(v) = prefs.edit().putBoolean(KEY_AUTO_INSTALL_UPDATES, v).apply()

    var relays: List<String>
        get() = splitList(prefs.getString(KEY_RELAYS, null))
        set(v) = prefs.edit().putString(KEY_RELAYS, v.joinToString("\n")).apply()

    var relayFirst: Boolean
        get() = prefs.getBoolean(KEY_RELAY_FIRST, false)
        set(v) = prefs.edit().putBoolean(KEY_RELAY_FIRST, v).apply()

    var verifyTls: Boolean
        get() = prefs.getBoolean(KEY_VERIFY_TLS, true)
        set(v) = prefs.edit().putBoolean(KEY_VERIFY_TLS, v).apply()

    /** Upstream `no_secure`: CF proxy and Workers over ws:// on port 80. */
    var noSecure: Boolean
        get() = prefs.getBoolean(KEY_NO_SECURE, false)
        set(v) = prefs.edit().putBoolean(KEY_NO_SECURE, v).apply()

    /**
     * True while the proxy runs and the user has not stopped it; lets the app
     * come back up after a self-update or after the process was killed.
     */
    var wasRunning: Boolean
        get() = prefs.getBoolean(KEY_WAS_RUNNING, false)
        // commit(): read right before the process may be killed by an update.
        @android.annotation.SuppressLint("ApplySharedPref")
        set(v) {
            prefs.edit().putBoolean(KEY_WAS_RUNNING, v).commit()
        }

    /** Version the user chose to skip, so it is not offered again. */
    var skippedUpdate: String
        get() = prefs.getString(KEY_UPDATE_SKIPPED, "").orEmpty()
        set(v) = prefs.edit().putString(KEY_UPDATE_SKIPPED, v).apply()

    var lastUpdateCheck: Long
        get() = prefs.getLong(KEY_UPDATE_LAST_CHECK, 0L)
        set(v) = prefs.edit().putLong(KEY_UPDATE_LAST_CHECK, v).apply()

    fun regenerateSecret(): String {
        val fresh = Crypto.randomHex(16)
        secret = fresh
        return fresh
    }

    /** Builds the engine config from the stored settings. */
    fun toProxyConfig(): ProxyConfig {
        val cfg = ProxyConfig()
        cfg.port = port
        cfg.host = host
        cfg.secret = secret
        cfg.dcRedirects = runCatching { ProxyConfig.parseDcIpList(dcIp) }
            .getOrElse { ProxyConfig.parseDcIpList(DEFAULT_DC_IP) }
        cfg.relays = relays
        cfg.relayFirst = relayFirst
        cfg.verifyTls = verifyTls
        cfg.disableSecure = noSecure
        cfg.bufferSize = maxOf(4, bufKb) * 1024
        cfg.poolSize = maxOf(0, poolSize)
        cfg.fallbackCfproxy = cfproxy
        cfg.cfproxyUserDomains =
            if (cfUserDomainEnabled) ProxyConfig.coerceDomainList(cfUserDomain) else emptyList()
        cfg.cfproxyWorkerDomains =
            if (cfWorkerEnabled) ProxyConfig.coerceDomainList(cfWorkerDomain) else emptyList()
        cfg.fakeTlsDomain = fakeTlsDomain
        cfg.proxyProtocol = false
        cfg.forceTestDc = forceTestDc
        cfg.fragmentClientHello = tlsSplit
        cfg.fragmentDelayMs = tlsSplitDelayMs.coerceIn(0, MAX_TLS_SPLIT_DELAY_MS)
        cfg.frontingFirst = frontingFirst
        cfg.frontingSni = frontingSni
        cfg.bypassVpn = bypassVpn
        cfg.mobileEvasion = mobileEvasion
        return cfg
    }

    /** Returns an error string, or null when the current settings are valid. */
    fun validate(): String? {
        if (port !in 1..65535) return "Port must be between 1 and 65535"
        if (host.isEmpty()) return "Host must not be empty"
        if (host != "0.0.0.0" && host != "127.0.0.1" && !ProxyConfig.isIpv4(host)) {
            return "Host must be an IPv4 address"
        }
        if (secret.length != 32 || !secret.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            return "Secret must be exactly 32 hex characters"
        }
        runCatching { ProxyConfig.parseDcIpList(dcIp) }
            .onFailure { return it.message ?: "Invalid DC:IP list" }
        if (bufKb < 4) return "Buffer size must be at least 4 KB"
        if (poolSize < 0) return "Pool size must be >= 0"
        val ftls = fakeTlsDomain
        if (ftls.isNotEmpty() && !ProxyConfig.isValidDomain(ftls)) {
            return "Fake TLS domain is not a valid domain name"
        }
        if (cfUserDomainEnabled && ProxyConfig.coerceDomainList(cfUserDomain).isEmpty()) {
            return "Enter at least one Cloudflare-proxied domain"
        }
        if (cfWorkerEnabled && ProxyConfig.coerceDomainList(cfWorkerDomain).isEmpty()) {
            return "Enter at least one Cloudflare Worker domain"
        }
        if (tlsSplitDelayMs !in 0..MAX_TLS_SPLIT_DELAY_MS) {
            return "TLS split delay must be between 0 and $MAX_TLS_SPLIT_DELAY_MS ms"
        }
        if (!ProxyConfig.isValidDomain(frontingSni)) {
            return "Fronting SNI is not a valid domain name"
        }
        val badRelays = RelayEndpoint.invalidEntries(relays)
        if (badRelays.isNotEmpty()) {
            return "Invalid relay address: ${badRelays.first()}"
        }
        if (relayFirst && relays.isEmpty() && !cfWorkerEnabled) {
            return "\"Relay first\" needs at least one relay or Worker"
        }
        return null
    }

    private fun splitList(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        return raw.split(',', ';', ' ', '\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
    }
}
