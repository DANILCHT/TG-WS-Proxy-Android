package com.flowseal.tgwsproxy.core

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import java.net.URLConnection

/**
 * Keeps the proxy's own upstream sockets outside an active VPN tunnel.
 *
 * Telegram reaches this proxy over loopback, which a VPN never captures, so
 * binding the *upstream* sockets to the underlying network is what actually
 * keeps Telegram's traffic out of the tunnel while the proxy runs. Nothing is
 * bound when no VPN is up, so the default behaviour is unchanged.
 *
 * DNS is resolved on the same network, otherwise the VPN's resolver would still
 * see (and possibly block) the lookups.
 */
object NetworkBinder {

    private const val CACHE_TTL_MS = 3_000L

    @Volatile
    private var appContext: Context? = null

    @Volatile
    var enabled: Boolean = false
        private set

    /**
     * Cleared once a bound connect fails while an unbound one succeeds, which
     * is what a lockdown VPN ("Block connections without VPN") looks like.
     */
    @Volatile
    private var bindingUsable = true

    @Volatile
    private var cached: Network? = null

    @Volatile
    private var cachedAt = 0L

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    fun configure(bypassVpn: Boolean) {
        enabled = bypassVpn
        bindingUsable = true
        cached = null
        cachedAt = 0L
    }

    /** Short status line for the startup banner. */
    fun describe(): String {
        if (!enabled) return "off"
        val ctx = appContext ?: return "unavailable"
        val cm = connectivity(ctx) ?: return "unavailable"
        if (!vpnActive(cm)) return "armed (no VPN active)"
        val net = pick() ?: return "no non-VPN network found"
        val caps = cm.getNetworkCapabilities(net)
        return "bypassing VPN via ${transportName(caps)}"
    }

    /** Active transport: "wifi", "cellular", "ethernet", "vpn" or "unknown". */
    fun activeTransport(): String {
        val ctx = appContext ?: return "unknown"
        val cm = connectivity(ctx) ?: return "unknown"
        if (Build.VERSION.SDK_INT >= 23) {
            val net = runCatching { cm.activeNetwork }.getOrNull() ?: return "unknown"
            val caps = cm.getNetworkCapabilities(net) ?: return "unknown"
            return transportId(caps, vpnFirst = true)
        }
        @Suppress("DEPRECATION")
        val info = runCatching { cm.activeNetworkInfo }.getOrNull() ?: return "unknown"
        if (!info.isConnected) return "unknown"
        @Suppress("DEPRECATION")
        return when (info.type) {
            ConnectivityManager.TYPE_WIFI -> "wifi"
            ConnectivityManager.TYPE_MOBILE -> "cellular"
            ConnectivityManager.TYPE_ETHERNET -> "ethernet"
            ConnectivityManager.TYPE_VPN -> "vpn"
            else -> "unknown"
        }
    }

    private fun transportId(caps: NetworkCapabilities, vpnFirst: Boolean = false): String = when {
        vpnFirst && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        else -> "unknown"
    }

    fun isCellular(): Boolean = activeTransport() == "cellular"

    /**
     * Connects a socket from [factory], binding it to a non-VPN network when
     * one is needed. Falls back to an unbound socket if binding turns out to be
     * blocked, so a lockdown VPN cannot take the proxy down entirely.
     */
    @Throws(Exception::class)
    fun connect(
        host: String,
        port: Int,
        timeoutMs: Int,
        factory: () -> Socket,
    ): Socket {
        val net = pick()
        if (net != null) {
            val socket = factory()
            try {
                net.bindSocket(socket)
                socket.connect(InetSocketAddress(resolve(net, host), port), timeoutMs)
                return socket
            } catch (e: Exception) {
                runCatching { socket.close() }
                // A timeout means the peer is unreachable, not that binding is
                // broken; retrying unbound would only double the wait.
                if (e is SocketTimeoutException) throw e
                Logger.d("Bound connect to $host:$port failed ($e), retrying unbound")
                val plain = factory()
                try {
                    plain.connect(InetSocketAddress(host, port), timeoutMs)
                } catch (retry: Exception) {
                    runCatching { plain.close() }
                    throw e
                }
                if (bindingUsable) {
                    bindingUsable = false
                    Logger.w(
                        "VPN bypass disabled for this session: the system refused " +
                            "to bind sockets to the underlying network ($e)"
                    )
                }
                return plain
            }
        }

        val socket = factory()
        try {
            socket.connect(InetSocketAddress(host, port), timeoutMs)
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw e
        }
        return socket
    }

    /** Binds an already-created socket; used for the local-IP probe. */
    fun bind(socket: DatagramSocket) {
        if (Build.VERSION.SDK_INT < 22) return
        val net = pick() ?: return
        runCatching { net.bindSocket(socket) }
    }

    /** Opens an HTTP(S) connection outside the tunnel when needed. */
    fun openConnection(url: URL): URLConnection {
        val net = pick() ?: return url.openConnection()
        return runCatching { net.openConnection(url) }.getOrElse { url.openConnection() }
    }

    private fun resolve(net: Network, host: String): InetAddress {
        if (ProxyConfig.isIpv4(host)) return InetAddress.getByName(host)
        val addrs = net.getAllByName(host)
        if (addrs.isNullOrEmpty()) throw java.net.UnknownHostException(host)
        return addrs[0]
    }

    private fun pick(): Network? {
        if (!enabled || !bindingUsable) return null
        val ctx = appContext ?: return null
        val now = System.currentTimeMillis()
        val hit = cached
        if (hit != null && now - cachedAt < CACHE_TTL_MS) return hit

        val cm = connectivity(ctx) ?: return null
        // Only step outside the default network when there is a tunnel to avoid.
        val chosen = if (vpnActive(cm)) selectNonVpn(cm) else null
        cached = chosen
        cachedAt = now
        return chosen
    }

    private fun connectivity(ctx: Context): ConnectivityManager? =
        ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    @Suppress("DEPRECATION")
    @SuppressLint("MissingPermission")
    private fun allNetworks(cm: ConnectivityManager): Array<Network> =
        runCatching { cm.allNetworks }.getOrDefault(emptyArray())

    private fun vpnActive(cm: ConnectivityManager): Boolean = allNetworks(cm).any { n ->
        cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    private fun selectNonVpn(cm: ConnectivityManager): Network? {
        var best: Network? = null
        var bestScore = -1
        for (net in allNetworks(cm)) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val score = score(caps)
            if (score > bestScore) {
                best = net
                bestScore = score
            }
        }
        return best
    }

    private fun score(caps: NetworkCapabilities): Int {
        var s = 0
        if (Build.VERSION.SDK_INT >= 23 &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        ) {
            s += 4
        }
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) s += 2
        else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) s += 1
        return s
    }

    private fun transportName(caps: NetworkCapabilities?): String = when {
        caps == null -> "unknown"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "mobile data"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        else -> "unknown transport"
    }
}
