package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.Tls
import org.junit.AfterClass
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket

/**
 * End-to-end checks against the real Telegram and Cloudflare servers. They
 * need network access, so they only run with `TGWS_LIVE=1` in the environment
 * (`TGWS_LIVE_WORKER=<domain>` adds a Cloudflare Worker check).
 *
 * Each check ends with Telegram answering an MTProto req_pq_multi, either
 * straight over an upstream WebSocket or through a running [ProxyEngine] the
 * way the Telegram app talks to it (obfuscated2 with the proxy secret).
 */
class LiveRoutesTest {

    companion object {
        private val live = System.getenv("TGWS_LIVE") == "1"
        private val worker = System.getenv("TGWS_LIVE_WORKER").orEmpty().trim()
        private val log = StringBuffer()
        private val listener: (String) -> Unit = { line -> println(line); log.append(line).append('\n') }

        @BeforeClass
        @JvmStatic
        fun setUp() {
            if (!live) return
            Logger.verbose = true
            Logger.addListener(listener)
            // The JDK's default HostnameVerifier rejects everything (Android's
            // does the real check), so certificate checks are off on the JVM.
            Tls.configure(ProxyConfig().apply { verifyTls = false; fragmentClientHello = true })
            Balancer.updateDomainsList(ProxyConfig.CFPROXY_DEFAULT_DOMAINS)
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            Logger.removeListener(listener)
        }
    }

    private fun cfConnect(base: String, dc: Int, tls: Boolean): RawWebSocket {
        val host = "kws$dc.$base"
        return RawWebSocket.connect(host = host, domain = host, timeoutMs = 8_000, secure = tls)
    }

    @Test
    fun cfProxyAnswersOverHttpAndTls() {
        assumeTrue(live)
        var http = 0
        var tls = 0
        for (base in ProxyConfig.CFPROXY_DEFAULT_DOMAINS.take(3)) {
            for (mode in listOf(false, true)) {
                val r = runCatching {
                    val ws = cfConnect(base, 2, mode)
                    try {
                        MtprotoProbe.check(ws, 2)
                    } finally {
                        ws.abort()
                    }
                }.getOrElse { "error: $it" }
                println("CF ${if (mode) "TLS" else "HTTP"} kws2.$base -> ${r ?: "resPQ"}")
                if (r == null) if (mode) tls++ else http++
            }
        }
        assertTrue("no CF domain answered over HTTP", http > 0)
        assertTrue("no CF domain answered over TLS", tls > 0)
    }

    @Test
    fun directWebSocketWithSplitClientHello() {
        assumeTrue(live)
        log.setLength(0)
        val ws = RawWebSocket.connect(
            host = "149.154.167.220", domain = "kws2.web.telegram.org", timeoutMs = 8_000,
            splitFirstPacket = true,
        )
        try {
            assertNull(MtprotoProbe.check(ws, 2))
        } finally {
            ws.abort()
        }
        assertTrue("ClientHello was not split", log.contains("ClientHello split at"))
    }

    /** A split plain HTTP request got flows frozen by Russian DPI: it must go out whole. */
    @Test
    fun plainHttpUpgradeIsNeverSplit() {
        assumeTrue(live)
        log.setLength(0)
        var answered = 0
        for (base in ProxyConfig.CFPROXY_DEFAULT_DOMAINS.take(3)) {
            val r = runCatching {
                val ws = RawWebSocket.connect(
                    host = "kws2.$base", domain = "kws2.$base", timeoutMs = 8_000, secure = false,
                    splitFirstPacket = true,
                )
                try {
                    MtprotoProbe.check(ws, 2)
                } finally {
                    ws.abort()
                }
            }.getOrElse { "error: $it" }
            println("HTTP via kws2.$base -> ${r ?: "resPQ"}")
            if (r == null) answered++
        }
        assertTrue("no CF domain answered over HTTP", answered > 0)
        assertTrue("plain HTTP request was split", !log.contains("split"))
    }

    // ------------------------------------------------------------ full engine

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun baseConfig(): ProxyConfig = ProxyConfig().apply {
        port = freePort()
        verifyTls = false
        poolSize = 2
    }

    /** Talks to the proxy like the Telegram app: obfuscated2 + secret, abridged. */
    private fun roundTrip(cfg: ProxyConfig, dcIdx: Int): Boolean {
        val secret = Const.fromHex(cfg.secret)
        Socket("127.0.0.1", cfg.port).use { s ->
            s.soTimeout = 30_000
            val init = Obfuscated.buildClientInit(secret, Const.PROTO_TAG_ABRIDGED, dcIdx)
            val enc = Crypto.CtrStream(Crypto.sha256(init.copyOfRange(8, 40), secret), init.copyOfRange(40, 56))
            enc.skip(64)
            val rev = Crypto.reversed(init.copyOfRange(8, 56))
            val dec = Crypto.CtrStream(Crypto.sha256(rev.copyOfRange(0, 32), secret), rev.copyOfRange(32, 48))

            val out = s.getOutputStream()
            out.write(init)
            out.write(enc.update(MtprotoProbe.reqPqPacket()))
            out.flush()

            val buf = java.io.ByteArrayOutputStream()
            val chunk = ByteArray(4096)
            val input = s.getInputStream()
            while (buf.size() < 25) {
                val n = input.read(chunk)
                if (n <= 0) break
                buf.write(chunk, 0, n)
            }
            return MtprotoProbe.isResPq(dec.update(buf.toByteArray()))
        }
    }

    private fun withEngine(cfg: ProxyConfig, block: () -> Unit) {
        Stats.reset()
        CfModes.reset()
        val engine = ProxyEngine(cfg)
        engine.start()
        try {
            block()
        } finally {
            engine.stop()
            println("stats: ${Stats.summary()} | cf: ${CfModes.describe()}")
        }
    }

    @Test
    fun engineDefaultRoute() {
        assumeTrue(live)
        val cfg = baseConfig()
        withEngine(cfg) {
            for (dc in listOf(2, 4, 1)) assertTrue("DC$dc", roundTrip(cfg, dc))
            // Second wave: learned routes and warm pools should answer too.
            for (dc in listOf(2, 4, 1)) assertTrue("DC$dc again", roundTrip(cfg, dc))
        }
    }

    @Test
    fun engineCloudflareOnly() {
        assumeTrue(live)
        val cfg = baseConfig().apply { dcRedirects = emptyMap() }
        withEngine(cfg) {
            for (dc in listOf(2, 4, 1)) assertTrue("DC$dc", roundTrip(cfg, dc))
            assertTrue("CF route not used", Stats.connectionsCfproxy.get() > 0)
        }
    }

    @Test
    fun engineCloudflareHttpOnly() {
        assumeTrue(live)
        val cfg = baseConfig().apply { dcRedirects = emptyMap(); disableSecure = true }
        withEngine(cfg) {
            assertTrue(roundTrip(cfg, 2))
            assertTrue(Stats.connectionsCfproxy.get() > 0)
        }
    }

    @Test
    fun engineMediaThroughCloudflare() {
        assumeTrue(live)
        val cfg = baseConfig().apply { dcRedirects = emptyMap() }
        withEngine(cfg) {
            println("media DC2 via CF -> ${roundTrip(cfg, -2)}")
            println("media DC4 via CF -> ${roundTrip(cfg, -4)}")
        }
    }

    @Test
    fun engineWorkerOnly() {
        assumeTrue(live && worker.isNotEmpty())
        val cfg = baseConfig().apply {
            dcRedirects = emptyMap()
            fallbackCfproxy = false
            cfproxyWorkerDomains = listOf(worker)
        }
        withEngine(cfg) {
            assertTrue(roundTrip(cfg, 2))
            assertTrue(roundTrip(cfg, 5))
            assertTrue("relay route not used", Stats.connectionsRelay.get() > 0)
        }
    }
}
