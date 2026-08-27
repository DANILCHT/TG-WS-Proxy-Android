package com.flowseal.tgwsproxy.net

import android.annotation.SuppressLint
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.NetworkBinder
import com.flowseal.tgwsproxy.core.ProxyConfig
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * TLS plumbing for upstream WS connections.
 *
 * The Python code uses an SSL context with `check_hostname = False` and
 * `verify_mode = CERT_NONE`, because it deliberately connects to a *DC IP*
 * while presenting a different SNI (domain fronting). Certificate validation
 * would always fail there. This is not a downgrade of the app's security model:
 * the MTProto payload inside is independently encrypted and authenticated by
 * Telegram's own protocol, and this socket carries nothing else.
 */
object Tls {

    /** Set from the engine config; applies to every upstream TLS handshake. */
    @Volatile
    var fragmentByDefault: Boolean = false
        private set

    @Volatile
    var fragmentDelayMs: Long = 0L
        private set

    fun configure(cfg: ProxyConfig) {
        fragmentByDefault = cfg.fragmentClientHello
        fragmentDelayMs = cfg.fragmentDelayMs.toLong()
    }

    @SuppressLint("CustomX509TrustManager")
    private val trustAll = object : X509TrustManager {
        @SuppressLint("TrustAllX509TrustManager")
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit

        @SuppressLint("TrustAllX509TrustManager")
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private val factory: SSLSocketFactory by lazy {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trustAll), java.security.SecureRandom())
        ctx.socketFactory
    }

    fun applySocketOpts(socket: Socket, bufferSize: Int) {
        runCatching { socket.tcpNoDelay = true }
        runCatching { socket.receiveBufferSize = bufferSize }
        runCatching { socket.sendBufferSize = bufferSize }
    }

    /**
     * Connects a plain TCP socket, routed around an active VPN when the user
     * asked for that. Used by the non-TLS fallbacks as well.
     */
    @Throws(Exception::class)
    fun connectPlain(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        bufferSize: Int,
        fragmentHandshake: Boolean = false,
    ): Socket = NetworkBinder.connect(host, port, connectTimeoutMs) {
        val s = if (fragmentHandshake) FragmentingSocket(fragmentDelayMs) else Socket()
        applySocketOpts(s, bufferSize)
        s
    }

    /**
     * Connects to [host]:[port] and completes a TLS handshake presenting [sni]
     * as the server name.
     *
     * When [fragmentHandshake] is set the ClientHello leaves in two TCP
     * segments split inside the SNI, which defeats filters that only inspect
     * the first packet of a connection.
     */
    fun connect(
        host: String,
        port: Int,
        sni: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        bufferSize: Int,
        fragmentHandshake: Boolean = fragmentByDefault,
    ): SSLSocket {
        val raw = connectPlain(host, port, connectTimeoutMs, bufferSize, fragmentHandshake)
        try {
            raw.soTimeout = readTimeoutMs

            val ssl = factory.createSocket(raw, sni, port, true) as SSLSocket
            applySocketOpts(ssl, bufferSize)
            setSni(ssl, sni)
            ssl.soTimeout = readTimeoutMs
            ssl.startHandshake()
            return ssl
        } catch (e: Throwable) {
            runCatching { raw.close() }
            throw e
        }
    }

    private fun setSni(ssl: SSLSocket, sni: String) {
        if (android.os.Build.VERSION.SDK_INT >= 24) {
            runCatching {
                val params = ssl.sslParameters
                params.serverNames = listOf(SNIHostName(sni))
                ssl.sslParameters = params
                return
            }
        }
        // API 21-23: Android's SSLSocketImpl exposes setHostname(String).
        runCatching {
            val m = ssl.javaClass.getMethod("setHostname", String::class.java)
            m.invoke(ssl, sni)
        }.onFailure {
            Logger.d("SNI could not be set for $sni: $it")
        }
    }
}
