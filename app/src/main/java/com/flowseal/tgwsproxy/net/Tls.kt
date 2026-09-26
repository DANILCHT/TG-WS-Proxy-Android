package com.flowseal.tgwsproxy.net

import android.annotation.SuppressLint
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.NetworkBinder
import com.flowseal.tgwsproxy.core.ProxyConfig
import java.net.Socket
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * TLS plumbing for upstream connections.
 *
 * Mirrors upstream 1.10.4 (`create_ssl_context`): certificates are verified
 * against the system trust store; the host name is checked too, except when
 * fronting, where the SNI is deliberately not the server's name and only the
 * chain is validated. Verification can be turned off in the settings for old
 * devices with an outdated trust store — the MTProto payload inside is
 * independently encrypted and authenticated by Telegram either way.
 */
object Tls {

    enum class Verify {
        /** Chain and host name. */
        FULL,

        /** Chain only: used when SNI intentionally differs from the server. */
        CHAIN,

        /** Nothing: explicit per-relay opt-out (self-signed relay certs). */
        NONE,
    }

    @Volatile
    var fragmentByDefault: Boolean = false
        private set

    @Volatile
    var fragmentDelayMs: Long = 0L
        private set

    /** Global switch from the settings; off downgrades every check to NONE. */
    @Volatile
    var verifyCertificates: Boolean = true
        private set

    fun configure(cfg: ProxyConfig) {
        fragmentByDefault = cfg.fragmentClientHello
        fragmentDelayMs = cfg.fragmentDelayMs.toLong()
        verifyCertificates = cfg.verifyTls
    }

    @SuppressLint("CustomX509TrustManager")
    private val trustAll = object : X509TrustManager {
        @SuppressLint("TrustAllX509TrustManager")
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit

        @SuppressLint("TrustAllX509TrustManager")
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private val insecureFactory: SSLSocketFactory by lazy {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trustAll), java.security.SecureRandom())
        ctx.socketFactory
    }

    private val verifyingFactory: SSLSocketFactory by lazy {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, tmf.trustManagers, java.security.SecureRandom())
        ctx.socketFactory
    }

    fun applySocketOpts(socket: Socket, bufferSize: Int) {
        runCatching { socket.tcpNoDelay = true }
        runCatching { socket.keepAlive = true }
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
     * Connects to [host]:[port] and completes a TLS handshake presenting [sni].
     *
     * When [fragmentHandshake] is set the ClientHello leaves in two TCP
     * segments split inside the SNI, which defeats filters that only inspect
     * the first packet of a connection.
     *
     * [forceVerify] ignores the global switch; used for GitHub and DoH, where a
     * spoofed answer would matter.
     */
    fun connect(
        host: String,
        port: Int,
        sni: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        bufferSize: Int,
        fragmentHandshake: Boolean = fragmentByDefault,
        verify: Verify = Verify.FULL,
        hostnameToVerify: String = sni,
        forceVerify: Boolean = false,
    ): SSLSocket {
        val mode = if (verifyCertificates || forceVerify) verify else Verify.NONE
        val raw = connectPlain(host, port, connectTimeoutMs, bufferSize, fragmentHandshake)
        try {
            raw.soTimeout = readTimeoutMs

            val factory = if (mode == Verify.NONE) insecureFactory else verifyingFactory
            val ssl = factory.createSocket(raw, sni, port, true) as SSLSocket
            applySocketOpts(ssl, bufferSize)
            setSni(ssl, sni)
            ssl.soTimeout = readTimeoutMs
            try {
                ssl.startHandshake()
            } catch (e: javax.net.ssl.SSLHandshakeException) {
                if (mode != Verify.NONE && isCertProblem(e)) {
                    Logger.w(
                        "TLS certificate check failed for $sni: ${e.message?.take(120)}. " +
                            "On old devices disable \"Verify TLS certificates\"."
                    )
                }
                throw e
            }
            if (mode == Verify.FULL &&
                !HttpsURLConnection.getDefaultHostnameVerifier().verify(hostnameToVerify, ssl.session)
            ) {
                runCatching { ssl.close() }
                throw SSLPeerUnverifiedException("certificate does not match $hostnameToVerify")
            }
            return ssl
        } catch (e: Throwable) {
            runCatching { raw.close() }
            throw e
        }
    }

    private fun isCertProblem(e: Exception): Boolean {
        var c: Throwable? = e
        while (c != null) {
            if (c is java.security.cert.CertificateException ||
                c is java.security.cert.CertPathValidatorException
            ) return true
            c = c.cause
        }
        return false
    }

    private fun setSni(ssl: SSLSocket, sni: String) {
        if (ProxyConfig.isIpv4(sni)) return // IP literals are not valid SNI
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
