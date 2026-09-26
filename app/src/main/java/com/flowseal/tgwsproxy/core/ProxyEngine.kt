package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.DataStream
import com.flowseal.tgwsproxy.net.Dns
import com.flowseal.tgwsproxy.net.FakeTls
import com.flowseal.tgwsproxy.net.FakeTlsStream
import com.flowseal.tgwsproxy.net.SocketStream
import com.flowseal.tgwsproxy.net.Tls
import java.io.EOFException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Port of proxy/tg_ws_proxy.py — the MTProto listener, obfuscated handshake
 * parsing, DC routing and the WS/fallback decision logic.
 */
class ProxyEngine(val config: ProxyConfig) {

    companion object {
        private const val LISTENER_RESTART_DELAY_MS = 1_000L
        private const val STATS_INTERVAL_MS = 60_000L
        private const val POOL_SWEEP_INTERVAL_MS = 5_000L
        private const val HANDSHAKE_READ_TIMEOUT_MS = 10_000
    }

    /** Snapshot of the values shown in the UI notification. */
    class State(
        val running: Boolean,
        val host: String,
        val port: Int,
        val secret: String,
        val fakeTlsDomain: String,
        val error: String? = null,
    )

    private val workers: ThreadPoolExecutor = ThreadPoolExecutor(
        4, 512, 60L, TimeUnit.SECONDS, SynchronousQueue(),
        ThreadPoolExecutor.CallerRunsPolicy(),
    )
    private val poolExecutor = Executors.newFixedThreadPool(6, daemonThreads("tg-ws-pool"))

    // Route attempts race each other, so they need their own threads; bounded
    // so a burst of Telegram connections cannot spawn threads without limit.
    private val connectExecutor = ThreadPoolExecutor(
        0, 256, 30L, TimeUnit.SECONDS, SynchronousQueue(), daemonThreads("tg-ws-connect"),
    )

    private val wsPool = WsPool(poolExecutor)
    private val relayPool = RelayPool(poolExecutor)
    private val router = Router(config, wsPool, relayPool, connectExecutor)
    private val domainRefresher = CfDomainRefresher(config)

    /** Settings as saved; [config] gets the per-network overrides on top. */
    private val baseConfig: ProxyConfig = config.copy()

    private val stopping = AtomicBoolean(false)

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var acceptThread: Thread? = null

    @Volatile
    private var houseKeeper: Thread? = null

    @Volatile
    var lastError: String? = null
        private set

    val isRunning: Boolean
        get() = serverSocket?.isClosed == false

    // ---------------------------------------------------------------- lifecycle

    /** Binds the listener. Throws if the port cannot be bound. */
    @Throws(Exception::class)
    fun start() {
        stopping.set(false)
        lastError = null
        Stats.reset()

        wsPool.reset()
        relayPool.reset()
        router.reset()
        Dns.clear()

        NetworkBinder.configure(config.bypassVpn)
        // Must happen before warmup below, which opens sockets immediately.
        applyNetworkProfile()

        val userCfDomains = config.cfproxyUserDomains
        if (userCfDomains.isNotEmpty()) {
            Balancer.updateDomainsList(userCfDomains)
            domainRefresher.stop()
        } else {
            domainRefresher.start()
        }

        val server = bind()
        serverSocket = server
        logBanner()

        val t = Thread({ acceptLoop() }, "tg-ws-accept")
        t.isDaemon = true
        acceptThread = t
        t.start()

        val hk = Thread({ houseKeepingLoop() }, "tg-ws-housekeeping")
        hk.isDaemon = true
        houseKeeper = hk
        hk.start()

        warmup()
        NetworkBinder.watch { onNetworkChanged() }
    }

    private fun warmup() {
        wsPool.warmup()
        relayPool.warmup(config.relayEndpoints(), allDcs = config.relayFirst)
    }

    /**
     * Re-derives the per-network overrides from [baseConfig]: on mobile data
     * the TLS split and fronting-first are forced when the user allowed that.
     */
    private fun applyNetworkProfile() {
        config.fragmentClientHello = baseConfig.fragmentClientHello
        config.frontingFirst = baseConfig.frontingFirst
        val forced = config.applyMobileProfile(NetworkBinder.isCellular())
        Tls.configure(config)
        wsPool.configure(config)
        relayPool.configure(config)
        if (forced) Logger.i("Mobile data active: TLS split + fronting-first forced")
    }

    /**
     * Every pooled socket, cooldown and learned route belongs to the previous
     * network; keeping them means a long stall on the first new connections.
     */
    private fun onNetworkChanged() {
        if (stopping.get()) return
        Dns.clear()
        router.reset()
        wsPool.flush()
        relayPool.flush()
        applyNetworkProfile()
        Logger.i("Network: ${NetworkBinder.activeTransport()}, VPN bypass: ${NetworkBinder.describe()}")
        warmup()
    }

    fun stop() {
        if (!stopping.compareAndSet(false, true)) return
        Logger.i("Stopping proxy")
        NetworkBinder.unwatch()
        domainRefresher.stop()
        runCatching { serverSocket?.close() }
        serverSocket = null
        acceptThread?.interrupt()
        houseKeeper?.interrupt()
        wsPool.reset()
        relayPool.reset()
        workers.shutdownNow()
        poolExecutor.shutdownNow()
        connectExecutor.shutdownNow()
        Logger.i("Proxy stopped. Final stats: ${Stats.summary()}")
    }

    fun state(): State = State(
        running = isRunning,
        host = config.host,
        port = config.port,
        secret = config.secret,
        fakeTlsDomain = config.fakeTlsDomain,
        error = lastError,
    )

    fun ddLink(): String {
        val linkHost = linkHost(config.host)
        return "tg://proxy?server=$linkHost&port=${config.port}&secret=dd${config.secret}"
    }

    fun eeLink(): String? {
        val ftls = config.fakeTlsDomain
        if (ftls.isEmpty()) return null
        val linkHost = linkHost(config.host)
        val domainHex = Const.toHex(ftls.toByteArray(Charsets.US_ASCII))
        return "tg://proxy?server=$linkHost&port=${config.port}" +
            "&secret=ee${config.secret}$domainHex"
    }

    fun tgLink(): String = eeLink() ?: ddLink()

    private fun bind(): ServerSocket {
        val server = ServerSocket()
        server.reuseAddress = true
        val addr = if (config.host == "0.0.0.0") {
            InetSocketAddress(config.port)
        } else {
            InetSocketAddress(InetAddress.getByName(config.host), config.port)
        }
        server.bind(addr, 256)
        return server
    }

    private fun logBanner() {
        val ftls = config.fakeTlsDomain
        Logger.i("=".repeat(60))
        Logger.i("  Telegram MTProto WS Bridge Proxy")
        Logger.i("  Listening on   ${config.host}:${config.port}")
        Logger.i("  Secret:        ${config.secret}")
        if (ftls.isNotEmpty()) Logger.i("  Fake TLS:      $ftls")
        Logger.i("  Target DC IPs:")
        for (dc in config.dcRedirects.keys.sorted()) {
            Logger.i("    DC$dc: ${config.dcRedirects[dc]}")
        }
        if (config.fallbackCfproxy) {
            val userDomain = if (config.cfproxyUserDomains.isNotEmpty()) {
                config.cfproxyUserDomains.joinToString(", ")
            } else {
                "auto"
            }
            Logger.i("  CF proxy:      enabled ($userDomain)")
        }
        if (config.cfproxyWorkerDomains.isNotEmpty()) {
            Logger.i("  CF worker:     enabled (${config.cfproxyWorkerDomains.joinToString(", ")})")
        }
        if (config.disableSecure) {
            Logger.i("  No secure:     enabled (port 80 for CF proxy/worker)")
        }
        val relays = RelayEndpoint.parseList(config.relays)
        if (relays.isNotEmpty()) {
            Logger.i(
                "  Relays:        ${relays.joinToString(", ")}" +
                    if (config.relayFirst) " (first)" else ""
            )
        }
        Logger.i("  TLS verify:    ${if (config.verifyTls) "on" else "off"}")
        Logger.i(
            "  TLS split:     " +
                if (config.fragmentClientHello) {
                    "enabled" + if (config.fragmentDelayMs > 0) " (+${config.fragmentDelayMs}ms)" else ""
                } else {
                    "disabled"
                }
        )
        if (config.frontingFirst) Logger.i("  Fronting SNI:  ${config.frontingSni} (first attempt)")
        Logger.i("  Network:       ${NetworkBinder.activeTransport()}")
        Logger.i("  VPN bypass:    ${NetworkBinder.describe()}")
        Logger.i("=".repeat(60))
        Logger.i("  Connect:")
        Logger.i("    ${tgLink()}")
        Logger.i("=".repeat(60))
    }

    private fun linkHost(host: String): String {
        if (host != "0.0.0.0") return host
        return runCatching {
            java.net.DatagramSocket().use { s ->
                NetworkBinder.bind(s)
                s.connect(InetAddress.getByName("8.8.8.8"), 80)
                s.localAddress.hostAddress ?: "127.0.0.1"
            }
        }.getOrDefault("127.0.0.1")
    }

    // -------------------------------------------------------------- accept loop

    private fun acceptLoop() {
        val secretBytes = Const.fromHex(config.secret)

        while (!stopping.get()) {
            val server = serverSocket ?: break
            val client = try {
                server.accept()
            } catch (e: Exception) {
                if (stopping.get()) break
                Logger.w("Listening socket died, restarting server: $e")
                runCatching { server.close() }
                Thread.sleep(LISTENER_RESTART_DELAY_MS)
                val restarted = try {
                    bind()
                } catch (e2: Exception) {
                    lastError = "Failed to restart server: $e2"
                    Logger.e("Failed to restart server", e2)
                    break
                }
                serverSocket = restarted
                Logger.w("Server restored, listening on ${config.host}:${config.port}")
                continue
            }

            workers.execute { handleClient(client, secretBytes) }
        }
    }

    private fun houseKeepingLoop() {
        var lastStats = System.currentTimeMillis()
        while (!stopping.get()) {
            try {
                Thread.sleep(POOL_SWEEP_INTERVAL_MS)
            } catch (_: InterruptedException) {
                return
            }
            runCatching { wsPool.sweep() }
            val now = System.currentTimeMillis()
            if (now - lastStats >= STATS_INTERVAL_MS) {
                lastStats = now
                Logger.i(
                    "stats: ${Stats.summary()} | ws_bl: ${router.blacklistSummary(now)} " +
                        "| routes: ${router.routeSummary(now)}"
                )
            }
        }
    }

    // ------------------------------------------------------- handshake handling

    private class ClientInit(
        val handshake: ByteArray,
        val stream: DataStream,
        val label: String,
    )

    /** Port of _read_client_init: PROXY protocol, Fake TLS, or plain obfs2. */
    private fun readClientInit(
        stream: SocketStream,
        secret: ByteArray,
        labelIn: String,
        masking: String,
    ): ClientInit? {
        var label = labelIn

        if (config.proxyProtocol) {
            val ppLine = try {
                stream.readLine()
            } catch (e: Exception) {
                Logger.d("[$label] disconnected during PROXY header")
                return null
            } ?: run {
                Logger.d("[$label] disconnected during PROXY header")
                return null
            }
            val ppText = ppLine.trim()
            if (ppText.startsWith("PROXY ")) {
                val parts = ppText.split(" ")
                if (parts.size >= 6) label = "${parts[2]}:${parts[4]}"
                Logger.d("[$label] PROXY protocol: $ppText")
            } else {
                Logger.d("[$label] expected PROXY header, got: ${ppText.take(60)}")
            }
        }

        val firstByte = try {
            stream.readExactly(1)
        } catch (e: EOFException) {
            Logger.d("[$label] client disconnected before handshake")
            return null
        }

        val first = firstByte[0].toInt() and 0xFF

        if (first == FakeTls.TLS_RECORD_HANDSHAKE && masking.isNotEmpty()) {
            val hdrRest = try {
                stream.readExactly(4)
            } catch (e: EOFException) {
                Logger.d("[$label] incomplete TLS record header")
                return null
            }
            val tlsHeader = firstByte + hdrRest
            val recordLen = ((tlsHeader[3].toInt() and 0xFF) shl 8) or (tlsHeader[4].toInt() and 0xFF)

            val recordBody = try {
                stream.readExactly(recordLen)
            } catch (e: EOFException) {
                Logger.d("[$label] incomplete TLS record body")
                return null
            }

            val clientHello = tlsHeader + recordBody
            val tlsResult = FakeTls.verifyClientHello(clientHello, secret)

            if (tlsResult == null) {
                Logger.d(
                    "[$label] Fake TLS verify failed (size=${clientHello.size} " +
                        "rec=$recordLen) -> masking"
                )
                FakeTls.proxyToMaskingDomain(stream, clientHello, masking, label)
                return null
            }

            Logger.d("[$label] Fake TLS handshake ok (ts=${tlsResult.timestamp})")

            val serverHello = FakeTls.buildServerHello(
                secret, tlsResult.clientRandom, tlsResult.sessionId,
            )
            stream.write(serverHello)
            stream.flush()

            val tlsStream = FakeTlsStream(stream)
            val handshake = try {
                tlsStream.readExactly(Const.HANDSHAKE_LEN)
            } catch (e: EOFException) {
                Logger.d("[$label] incomplete obfs2 init inside TLS")
                return null
            }
            return ClientInit(handshake, tlsStream, label)
        }

        if (masking.isNotEmpty()) {
            Logger.d("[$label] non-TLS byte 0x%02X -> HTTP redirect".format(first))
            val redirect = (
                "HTTP/1.1 301 Moved Permanently\r\n" +
                    "Location: https://$masking/\r\n" +
                    "Content-Length: 0\r\n" +
                    "Connection: close\r\n\r\n"
                ).toByteArray(Charsets.ISO_8859_1)
            runCatching {
                stream.write(redirect)
                stream.flush()
            }
            return null
        }

        val rest = try {
            stream.readExactly(Const.HANDSHAKE_LEN - 1)
        } catch (e: EOFException) {
            Logger.d("[$label] client disconnected before handshake")
            return null
        }
        return ClientInit(firstByte + rest, stream, label)
    }

    // ------------------------------------------------------------ client worker

    private fun handleClient(socket: Socket, secret: ByteArray) {
        Stats.connectionsTotal.incrementAndGet()
        Stats.connectionsActive.incrementAndGet()

        var label = "?"
        var stream: SocketStream? = null

        try {
            label = "${socket.inetAddress?.hostAddress}:${socket.port}"
            Tls.applySocketOpts(socket, config.bufferSize)
            socket.soTimeout = HANDSHAKE_READ_TIMEOUT_MS
            val s = SocketStream(socket, 32 * 1024)
            stream = s

            val init = readClientInit(s, secret, label, config.fakeTlsDomain) ?: return
            label = init.label
            val clientStream = init.stream

            val result = Obfuscated.tryHandshake(init.handshake, secret)
            if (result == null) {
                Stats.connectionsBad.incrementAndGet()
                Logger.w("[$label] bad handshake (wrong secret or proto)")
                drain(clientStream)
                return
            }

            // The obfuscated handshake is done; long-lived sessions must not
            // time out on idle, so drop the read deadline.
            socket.soTimeout = 0

            var dc = result.dcId
            val isMedia = result.isMedia
            val protoTag = result.protoTag

            val isTestDc = config.forceTestDc || dc >= 10000
            if (dc >= 10000) {
                Logger.i("[$label] test DC$dc -> DC${dc - 10000}")
                dc -= 10000
            }

            val protoInt = Obfuscated.protoInt(protoTag)

            val dcIdx = if (isMedia) -dc else dc
            Logger.d(
                "[$label] handshake ok: DC$dc${if (isMedia) " media" else ""} " +
                    "proto=0x%08X".format(protoInt)
            )

            val relayInit = Obfuscated.generateRelayInit(protoTag, dcIdx)
            val ctx = Obfuscated.buildCryptoCtx(result.decPrekeyAndIv, secret, relayInit)

            router.serve(clientStream, label, dc, isTestDc, isMedia, relayInit, ctx, protoInt)
        } catch (e: SocketTimeoutException) {
            Logger.w("[$label] timeout during handshake")
        } catch (e: EOFException) {
            Logger.d("[$label] client disconnected")
        } catch (e: Exception) {
            Logger.e("[$label] unexpected: $e", e)
        } finally {
            Stats.connectionsActive.decrementAndGet()
            runCatching { stream?.close() }
            runCatching { socket.close() }
        }
    }

    private fun daemonThreads(name: String) = java.util.concurrent.ThreadFactory { r ->
        Thread(r, name).apply { isDaemon = true }
    }

    /** Mirrors the Python "read until the client gives up" path on bad secrets. */
    private fun drain(stream: DataStream) {
        val buf = ByteArray(4096)
        runCatching {
            stream.setReadTimeout(5_000)
            while (stream.read(buf, 0, buf.size) > 0) { /* discard */ }
        }
    }
}
