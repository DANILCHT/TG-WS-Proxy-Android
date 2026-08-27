package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.DataStream
import com.flowseal.tgwsproxy.net.FakeTls
import com.flowseal.tgwsproxy.net.FakeTlsStream
import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.SocketStream
import com.flowseal.tgwsproxy.net.Tls
import com.flowseal.tgwsproxy.net.WsHandshakeError
import java.io.EOFException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
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
        private const val IP_FAIL_COOLDOWN_MS = 3_600_000L
        private const val DC_FAIL_COOLDOWN_MS = 60_000L
        private const val WS_FAIL_TIMEOUT_MS = 2_000
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
    private val poolExecutor = Executors.newFixedThreadPool(6)

    private val wsPool = WsPool(poolExecutor)
    private val cfWorkerPool = CfWorkerPool(poolExecutor)
    private val fallback = Fallback(config, cfWorkerPool)
    private val domainRefresher = CfDomainRefresher(config)

    // Collections.newSetFromMap instead of ConcurrentHashMap.newKeySet: the
    // latter's KeySetView methods are only desugared from API 24.
    private val wsBlacklist: MutableSet<String> =
        java.util.Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
    private val dcFailUntil = ConcurrentHashMap<String, Long>()
    private val ipFailUntil = ConcurrentHashMap<String, Long>()

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
        cfWorkerPool.reset()
        wsBlacklist.clear()
        dcFailUntil.clear()
        ipFailUntil.clear()

        wsPool.configure(config)
        cfWorkerPool.configure(config)
        // Must happen before warmup below, which opens sockets immediately.
        Tls.configure(config)
        NetworkBinder.configure(config.bypassVpn)

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

        wsPool.warmup()
        cfWorkerPool.warmup()
    }

    fun stop() {
        if (!stopping.compareAndSet(false, true)) return
        Logger.i("Stopping proxy")
        domainRefresher.stop()
        runCatching { serverSocket?.close() }
        serverSocket = null
        acceptThread?.interrupt()
        houseKeeper?.interrupt()
        wsPool.reset()
        cfWorkerPool.reset()
        workers.shutdownNow()
        poolExecutor.shutdownNow()
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
        Logger.i(
            "  TLS split:     " +
                if (config.fragmentClientHello) {
                    "enabled" + if (config.fragmentDelayMs > 0) " (+${config.fragmentDelayMs}ms)" else ""
                } else {
                    "disabled"
                }
        )
        if (config.frontingFirst) Logger.i("  Fronting SNI:  ${config.frontingSni} (first attempt)")
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
                val bl = if (wsBlacklist.isEmpty()) "none" else {
                    wsBlacklist.sorted().joinToString(", ") { "DC$it" }
                }
                Logger.i("stats: ${Stats.summary()} | ws_bl: $bl")
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

            val dcKey = "$dc${if (isTestDc) "t" else ""}${if (isMedia) "m" else ""}"
            val mediaTag = if (isMedia) " media" else ""
            val now = System.currentTimeMillis()
            val wsPath = if (isTestDc) Const.WS_PATH_TEST else Const.WS_PATH
            val target = config.dcRedirects[dc]
            val isAnyCfFallback = config.fallbackCfproxy || config.cfproxyWorkerDomains.isNotEmpty()

            val ipCooldownActive = target != null &&
                now < (ipFailUntil[target] ?: 0L) && isAnyCfFallback

            if (target == null || dcKey in wsBlacklist || ipCooldownActive) {
                when {
                    target == null -> Logger.i("[$label] DC$dc not in config -> fallback")
                    dcKey in wsBlacklist ->
                        Logger.i("[$label] DC$dc$mediaTag WS blacklisted -> fallback")
                    else ->
                        Logger.i("[$label] DC$dc$mediaTag WS connect to $target was timed out -> fallback")
                }
                val splitter = runCatching { MsgSplitter(relayInit, protoInt) }.getOrNull()
                val ok = fallback.doFallback(
                    clientStream, relayInit, label, dc, isTestDc, isMedia, mediaTag, ctx, splitter,
                )
                if (!ok) Logger.w("[$label] DC$dc$mediaTag no fallback available")
                return
            }

            val wsTimeout = if (now < (dcFailUntil[dcKey] ?: 0L)) WS_FAIL_TIMEOUT_MS else 5_000
            val domains = Const.wsDomains(dc, isMedia)

            var ws: RawWebSocket? = null
            var wsFailedRedirect = false
            var wsTimedOut = false
            var allRedirects = true

            val allowPoolRefill = now >= (ipFailUntil[target] ?: 0L)
            if (!isTestDc) {
                ws = wsPool.get(dc, isMedia, target, domains, allowRefill = allowPoolRefill)
                if (ws != null) {
                    Logger.i("[$label] DC$dc$mediaTag -> pool hit via $target")
                }
            }

            if (ws == null) {
                for (domain in domains) {
                    Logger.i("[$label] DC$dc$mediaTag -> wss://$domain$wsPath via $target")
                    try {
                        ws = RawWebSocket.connect(
                            host = target, domain = domain, timeoutMs = wsTimeout,
                            path = wsPath, bufferSize = config.bufferSize,
                        )
                        allRedirects = false
                        break
                    } catch (e: WsHandshakeError) {
                        Stats.wsErrors.incrementAndGet()
                        if (e.isRedirect) {
                            wsFailedRedirect = true
                            Logger.w(
                                "[$label] DC$dc$mediaTag got ${e.statusCode} from $domain " +
                                    "-> ${e.location ?: "?"}"
                            )
                            continue
                        }
                        allRedirects = false
                        Logger.w("[$label] DC$dc$mediaTag WS handshake: ${e.statusLine}")
                    } catch (e: SocketTimeoutException) {
                        Stats.wsErrors.incrementAndGet()
                        wsTimedOut = true
                        Logger.w("[$label] DC$dc$mediaTag WS connect timed out via $domain")
                        break
                    } catch (e: Exception) {
                        Stats.wsErrors.incrementAndGet()
                        allRedirects = false
                        Logger.w("[$label] DC$dc$mediaTag WS connect failed: $e")
                    }
                }
            }

            if (ws == null) {
                if (wsTimedOut) {
                    ipFailUntil[target] = now + IP_FAIL_COOLDOWN_MS
                    Logger.i(
                        "[$label] DC$dc$mediaTag WS connect to $target timed out, " +
                            "cooldown for ${IP_FAIL_COOLDOWN_MS / 1000}s"
                    )
                }
                if (wsFailedRedirect && allRedirects) {
                    wsBlacklist.add(dcKey)
                    Logger.w("[$label] DC$dc$mediaTag blacklisted for WS (all 302)")
                } else if (wsFailedRedirect) {
                    dcFailUntil[dcKey] = now + DC_FAIL_COOLDOWN_MS
                } else {
                    dcFailUntil[dcKey] = now + DC_FAIL_COOLDOWN_MS
                    Logger.i(
                        "[$label] DC$dc$mediaTag WS cooldown for ${DC_FAIL_COOLDOWN_MS / 1000}s"
                    )
                }

                val splitterFb = runCatching { MsgSplitter(relayInit, protoInt) }.getOrNull()
                val ok = fallback.doFallback(
                    clientStream, relayInit, label, dc, isTestDc, isMedia, mediaTag, ctx, splitterFb,
                )
                if (ok) Logger.i("[$label] DC$dc$mediaTag fallback closed")
                return
            }

            dcFailUntil.remove(dcKey)
            ipFailUntil.remove(target)
            wsPool.reportSuccess(dc, isMedia)
            Stats.connectionsWs.incrementAndGet()

            val splitter = runCatching {
                MsgSplitter(relayInit, protoInt).also {
                    Logger.d("[$label] MsgSplitter activated for proto=0x%08X".format(protoInt))
                }
            }.getOrNull()

            ws.setReadTimeout(0)
            ws.send(relayInit)
            Bridge.bridgeWsReencrypt(clientStream, ws, label, ctx, dc, isMedia, splitter)
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

    /** Mirrors the Python "read until the client gives up" path on bad secrets. */
    private fun drain(stream: DataStream) {
        val buf = ByteArray(4096)
        runCatching {
            stream.setReadTimeout(5_000)
            while (stream.read(buf, 0, buf.size) > 0) { /* discard */ }
        }
    }
}
