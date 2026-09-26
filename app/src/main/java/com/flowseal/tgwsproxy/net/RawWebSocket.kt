package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Crypto
import com.flowseal.tgwsproxy.core.Logger
import java.io.OutputStream
import java.net.Socket

class WsHandshakeError(
    val statusCode: Int,
    val statusLine: String,
    val headers: Map<String, String> = emptyMap(),
    val location: String? = null,
) : Exception("HTTP $statusCode: $statusLine") {
    val isRedirect: Boolean
        get() = statusCode == 301 || statusCode == 302 || statusCode == 303 ||
            statusCode == 307 || statusCode == 308
}

/**
 * Port of proxy/raw_websocket.py — a minimal RFC 6455 client that only does
 * what the MTProto bridge needs: masked binary frames, ping/pong, close.
 */
class RawWebSocket private constructor(
    private val socket: Socket,
    private val stream: SocketStream,
) {

    companion object {
        const val OP_CONT = 0x0
        const val OP_TEXT = 0x1
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA

        const val MAX_MESSAGE_LEN = 16 * 1024 * 1024

        private val CLOSE_REASONS = mapOf(
            1000 to "normal", 1001 to "going_away", 1002 to "protocol_error",
            1003 to "unsupported_data", 1006 to "abnormal", 1007 to "bad_data",
            1008 to "policy_violation", 1009 to "too_big",
            1010 to "missing_extension", 1011 to "internal_error",
        )

        /**
         * Opens a WebSocket to [host] (an IP or hostname) using [domain] for
         * the HTTP Host header and [sni] (defaults to [domain]) for TLS.
         *
         * [secure] = false is upstream's `--no-secure`: plain ws:// on port 80.
         * [verify] defaults to a full check, or chain-only when fronting.
         */
        @Throws(Exception::class)
        fun connect(
            host: String,
            domain: String,
            timeoutMs: Int = 10_000,
            path: String = "/apiws",
            sni: String? = null,
            bufferSize: Int = 256 * 1024,
            secure: Boolean = true,
            port: Int = if (secure) 443 else 80,
            verify: Tls.Verify? = null,
            connectTimeoutMs: Int = minOf(timeoutMs, 10_000),
        ): RawWebSocket {
            val serverName = sni ?: domain

            val sock: Socket = if (secure) {
                Tls.connect(
                    host = host,
                    port = port,
                    sni = serverName,
                    connectTimeoutMs = connectTimeoutMs,
                    readTimeoutMs = timeoutMs,
                    bufferSize = bufferSize,
                    verify = verify ?: if (serverName == domain) Tls.Verify.FULL else Tls.Verify.CHAIN,
                    hostnameToVerify = serverName,
                )
            } else {
                Tls.connectPlain(host, port, connectTimeoutMs, bufferSize).also {
                    it.soTimeout = timeoutMs
                }
            }

            val stream = SocketStream(sock, 32 * 1024)
            try {
                val wsKey = Crypto.base64(Crypto.randomBytes(16))

                val req = buildString {
                    append("GET ").append(path).append(" HTTP/1.1\r\n")
                    append("Host: ").append(domain).append("\r\n")
                    append("Upgrade: websocket\r\n")
                    append("Connection: Upgrade\r\n")
                    append("Sec-WebSocket-Key: ").append(wsKey).append("\r\n")
                    append("Sec-WebSocket-Version: 13\r\n")
                    append("Sec-WebSocket-Protocol: binary\r\n")
                    append("\r\n")
                }
                stream.write(req.toByteArray(Charsets.ISO_8859_1))
                stream.flush()

                val responseLines = ArrayList<String>()
                while (true) {
                    val line = stream.readLine() ?: break
                    val trimmed = line.trim()
                    if (trimmed.isEmpty()) break
                    responseLines.add(trimmed)
                    if (responseLines.size > 100) break
                }

                if (responseLines.isEmpty()) {
                    stream.close()
                    throw WsHandshakeError(0, "empty response")
                }

                val firstLine = responseLines[0]
                val parts = firstLine.split(" ", limit = 3)
                val statusCode = if (parts.size >= 2) parts[1].toIntOrNull() ?: 0 else 0

                if (statusCode == 101) {
                    return RawWebSocket(sock, stream)
                }

                val headers = HashMap<String, String>()
                for (hl in responseLines.drop(1)) {
                    val i = hl.indexOf(':')
                    if (i > 0) {
                        headers[hl.substring(0, i).trim().lowercase()] = hl.substring(i + 1).trim()
                    }
                }
                stream.close()
                throw WsHandshakeError(statusCode, firstLine, headers, headers["location"])
            } catch (e: Throwable) {
                stream.close()
                throw e
            }
        }

        private fun xorMaskInto(
            data: ByteArray, off: Int, len: Int,
            mask: ByteArray, out: ByteArray, outOff: Int,
        ) = WsFraming.xorMaskInto(data, off, len, mask, out, outOff)
    }

    @Volatile
    var closed: Boolean = false
        private set

    /** Timestamp used by the connection pools to expire idle sockets. */
    @Volatile
    var createdAtNanos: Long = System.nanoTime()

    private val writeLock = Any()
    private val output: OutputStream = socket.getOutputStream()
    private val frag = java.io.ByteArrayOutputStream()

    val isBroken: Boolean
        get() = closed || socket.isClosed || socket.isInputShutdown || socket.isOutputShutdown

    fun setReadTimeout(ms: Int) {
        runCatching { socket.soTimeout = ms }
    }

    @Throws(Exception::class)
    fun send(data: ByteArray) {
        if (closed) throw java.io.IOException("WebSocket closed")
        val frame = buildFrame(OP_BINARY, data, 0, data.size, mask = true)
        synchronized(writeLock) {
            output.write(frame)
            output.flush()
        }
    }

    @Throws(Exception::class)
    fun sendBatch(parts: List<ByteArray>) {
        if (closed) throw java.io.IOException("WebSocket closed")
        synchronized(writeLock) {
            for (p in parts) output.write(buildFrame(OP_BINARY, p, 0, p.size, mask = true))
            output.flush()
        }
    }

    /** Returns the next application message, or null when the peer closed. */
    @Throws(Exception::class)
    fun recv(): ByteArray? {
        while (!closed) {
            val f = readFrame()
            when (f.opcode) {
                OP_CLOSE -> {
                    closed = true
                    val (code, reason) = parseClose(f.payload)
                    Logger.d("WS OP_CLOSE from upstream: code=$code reason='$reason'")
                    runCatching {
                        val echo = if (f.payload.size >= 2) f.payload.copyOfRange(0, 2) else ByteArray(0)
                        synchronized(writeLock) {
                            output.write(buildFrame(OP_CLOSE, echo, 0, echo.size, mask = true))
                            output.flush()
                        }
                    }
                    return null
                }

                OP_PING -> {
                    runCatching {
                        synchronized(writeLock) {
                            output.write(buildFrame(OP_PONG, f.payload, 0, f.payload.size, mask = true))
                            output.flush()
                        }
                    }
                    continue
                }

                OP_PONG -> continue

                OP_CONT, OP_TEXT, OP_BINARY -> {
                    if (f.fin && frag.size() == 0) return f.payload
                    frag.write(f.payload)
                    if (frag.size() > MAX_MESSAGE_LEN) {
                        throw java.io.IOException("WS message too large: ${frag.size()} bytes")
                    }
                    if (!f.fin) continue
                    val message = frag.toByteArray()
                    frag.reset()
                    return message
                }

                else -> continue
            }
        }
        return null
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching {
            synchronized(writeLock) {
                output.write(buildFrame(OP_CLOSE, ByteArray(0), 0, 0, mask = true))
                output.flush()
            }
        }
        runCatching { socket.close() }
        runCatching { stream.close() }
    }

    /** Drops the socket without the closing handshake (used on hard errors). */
    fun abort() {
        closed = true
        runCatching { socket.close() }
    }

    private class Frame(val opcode: Int, val payload: ByteArray, val fin: Boolean)

    @Throws(Exception::class)
    private fun readFrame(): Frame {
        val hdr = stream.readExactly(2)
        val fin = (hdr[0].toInt() and 0x80) != 0
        val opcode = hdr[0].toInt() and 0x0F
        var length = (hdr[1].toInt() and 0x7F).toLong()

        if (length == 126L) {
            val ext = stream.readExactly(2)
            length = ((ext[0].toInt() and 0xFF).toLong() shl 8) or (ext[1].toInt() and 0xFF).toLong()
        } else if (length == 127L) {
            val ext = stream.readExactly(8)
            length = 0
            for (b in ext) length = (length shl 8) or (b.toInt() and 0xFF).toLong()
        }

        if (length > MAX_MESSAGE_LEN) {
            throw java.io.IOException("WS frame too large: $length bytes")
        }

        val masked = (hdr[1].toInt() and 0x80) != 0
        return if (masked) {
            val maskKey = stream.readExactly(4)
            val payload = stream.readExactly(length.toInt())
            xorMaskInto(payload, 0, payload.size, maskKey, payload, 0)
            Frame(opcode, payload, fin)
        } else {
            Frame(opcode, stream.readExactly(length.toInt()), fin)
        }
    }

    private fun parseClose(payload: ByteArray?): Pair<Int?, String> {
        if (payload == null || payload.size < 2) return null to ""
        return runCatching {
            val code = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
            val text = String(payload, 2, payload.size - 2, Charsets.UTF_8)
            val name = CLOSE_REASONS[code]
            code to (if (name != null) "$text ($name)" else text)
        }.getOrDefault(null to "")
    }

    private fun buildFrame(
        opcode: Int,
        data: ByteArray,
        off: Int,
        len: Int,
        mask: Boolean,
    ): ByteArray = WsFraming.buildFrame(opcode, data, off, len, mask)
}

/**
 * RFC 6455 frame encoding, split out from [RawWebSocket] so the wire format can
 * be unit-tested without a socket.
 */
internal object WsFraming {

    // One generator per thread: the shared SecureRandom is synchronized and
    // every outgoing frame needs a fresh mask.
    private val maskRng = object : ThreadLocal<java.security.SecureRandom>() {
        override fun initialValue() = java.security.SecureRandom()
    }

    fun xorMaskInto(
        data: ByteArray, off: Int, len: Int,
        mask: ByteArray, out: ByteArray, outOff: Int,
    ) {
        for (i in 0 until len) {
            out[outOff + i] = (data[off + i].toInt() xor mask[i and 3].toInt()).toByte()
        }
    }

    fun buildFrame(
        opcode: Int,
        data: ByteArray,
        off: Int,
        len: Int,
        mask: Boolean,
        maskKey: ByteArray = maskRng.get()!!.let { r -> ByteArray(4).also { r.nextBytes(it) } },
    ): ByteArray {
        val fb = (0x80 or opcode).toByte()
        if (!mask) {
            return when {
                len < 126 -> ByteArray(2 + len).also {
                    it[0] = fb; it[1] = len.toByte()
                    System.arraycopy(data, off, it, 2, len)
                }

                len < 65536 -> ByteArray(4 + len).also {
                    it[0] = fb; it[1] = 126
                    it[2] = ((len shr 8) and 0xFF).toByte()
                    it[3] = (len and 0xFF).toByte()
                    System.arraycopy(data, off, it, 4, len)
                }

                else -> ByteArray(10 + len).also {
                    it[0] = fb; it[1] = 127
                    for (i in 0 until 8) {
                        it[2 + i] = ((len.toLong() shr (8 * (7 - i))) and 0xFF).toByte()
                    }
                    System.arraycopy(data, off, it, 10, len)
                }
            }
        }

        return when {
            len < 126 -> ByteArray(6 + len).also {
                it[0] = fb; it[1] = (0x80 or len).toByte()
                System.arraycopy(maskKey, 0, it, 2, 4)
                xorMaskInto(data, off, len, maskKey, it, 6)
            }

            len < 65536 -> ByteArray(8 + len).also {
                it[0] = fb; it[1] = (0x80 or 126).toByte()
                it[2] = ((len shr 8) and 0xFF).toByte()
                it[3] = (len and 0xFF).toByte()
                System.arraycopy(maskKey, 0, it, 4, 4)
                xorMaskInto(data, off, len, maskKey, it, 8)
            }

            else -> ByteArray(14 + len).also {
                it[0] = fb; it[1] = (0x80 or 127).toByte()
                for (i in 0 until 8) {
                    it[2 + i] = ((len.toLong() shr (8 * (7 - i))) and 0xFF).toByte()
                }
                System.arraycopy(maskKey, 0, it, 10, 4)
                xorMaskInto(data, off, len, maskKey, it, 14)
            }
        }
    }
}

