package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Crypto
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.Stats
import java.io.EOFException
import kotlin.concurrent.thread

/**
 * Port of proxy/fake_tls.py — the `ee`-secret Fake TLS transport.
 */
object FakeTls {

    const val TLS_RECORD_HANDSHAKE = 0x16
    const val TLS_RECORD_CCS = 0x14
    const val TLS_RECORD_APPDATA = 0x17

    private const val CLIENT_RANDOM_OFFSET = 11
    private const val CLIENT_RANDOM_LEN = 32
    private const val SESSION_ID_OFFSET = 44
    private const val SESSION_ID_LEN = 32

    private const val TIMESTAMP_TOLERANCE = 120L
    const val TLS_APPDATA_MAX = 16384

    private val CCS_FRAME = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

    private val SERVER_HELLO_TEMPLATE: ByteArray = run {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x7a))
        out.write(byteArrayOf(0x02, 0x00, 0x00, 0x76))
        out.write(byteArrayOf(0x03, 0x03))
        out.write(ByteArray(32))
        out.write(byteArrayOf(0x20))
        out.write(ByteArray(32))
        out.write(byteArrayOf(0x13, 0x01, 0x00))
        out.write(byteArrayOf(0x00, 0x2e))
        out.write(byteArrayOf(0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20))
        out.write(ByteArray(32))
        out.write(byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04))
        out.toByteArray()
    }

    private const val SH_RANDOM_OFF = 11
    private const val SH_SESSID_OFF = 44
    private const val SH_PUBKEY_OFF = 89

    class ClientHello(
        val clientRandom: ByteArray,
        val sessionId: ByteArray,
        val timestamp: Long,
    )

    /**
     * Validates the HMAC-stamped ClientHello. Returns null when this is not our
     * client (caller then forwards the bytes to the masking domain).
     */
    fun verifyClientHello(data: ByteArray, secret: ByteArray): ClientHello? {
        val n = data.size
        if (n < 43) return null
        if ((data[0].toInt() and 0xFF) != TLS_RECORD_HANDSHAKE) return null
        if (data[5].toInt() != 0x01) return null

        val clientRandom = data.copyOfRange(
            CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN,
        )

        val zeroed = data.copyOf()
        java.util.Arrays.fill(
            zeroed, CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN, 0,
        )

        val expected = Crypto.hmacSha256(secret, zeroed)
        if (!Crypto.constantTimeEquals(expected, clientRandom, 28)) return null

        var ts = 0L
        for (i in 0 until 4) {
            val b = (clientRandom[28 + i].toInt() xor expected[28 + i].toInt()) and 0xFF
            ts = ts or (b.toLong() shl (8 * i)) // little-endian
        }

        val now = System.currentTimeMillis() / 1000
        if (Math.abs(now - ts) > TIMESTAMP_TOLERANCE) return null

        var sessionId = ByteArray(SESSION_ID_LEN)
        if (n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43].toInt() == 0x20) {
            sessionId = data.copyOfRange(SESSION_ID_OFFSET, SESSION_ID_OFFSET + SESSION_ID_LEN)
        }

        return ClientHello(clientRandom, sessionId, ts)
    }

    fun buildServerHello(
        secret: ByteArray,
        clientRandom: ByteArray,
        sessionId: ByteArray,
    ): ByteArray {
        val sh = SERVER_HELLO_TEMPLATE.copyOf()
        System.arraycopy(sessionId, 0, sh, SH_SESSID_OFF, 32)
        System.arraycopy(Crypto.randomBytes(32), 0, sh, SH_PUBKEY_OFF, 32)

        val encryptedSize = 1900 + Crypto.randomInt(201) // 1900..2100
        val encryptedData = Crypto.randomBytes(encryptedSize)

        val out = java.io.ByteArrayOutputStream()
        out.write(sh)
        out.write(CCS_FRAME)
        out.write(byteArrayOf(0x17, 0x03, 0x03))
        out.write(byteArrayOf(((encryptedSize shr 8) and 0xFF).toByte(), (encryptedSize and 0xFF).toByte()))
        out.write(encryptedData)
        val response = out.toByteArray()

        val hmacInput = ByteArray(clientRandom.size + response.size)
        System.arraycopy(clientRandom, 0, hmacInput, 0, clientRandom.size)
        System.arraycopy(response, 0, hmacInput, clientRandom.size, response.size)
        val serverRandom = Crypto.hmacSha256(secret, hmacInput)

        val finalBytes = response.copyOf()
        System.arraycopy(serverRandom, 0, finalBytes, SH_RANDOM_OFF, 32)
        return finalBytes
    }

    fun wrapTlsRecord(data: ByteArray, off: Int, len: Int): ByteArray {
        val records = (len + TLS_APPDATA_MAX - 1) / TLS_APPDATA_MAX
        val out = ByteArray(len + records * 5)
        var src = off
        var dst = 0
        var remaining = len
        while (remaining > 0) {
            val chunk = minOf(remaining, TLS_APPDATA_MAX)
            out[dst] = 0x17
            out[dst + 1] = 0x03
            out[dst + 2] = 0x03
            out[dst + 3] = ((chunk shr 8) and 0xFF).toByte()
            out[dst + 4] = (chunk and 0xFF).toByte()
            System.arraycopy(data, src, out, dst + 5, chunk)
            dst += 5 + chunk
            src += chunk
            remaining -= chunk
        }
        return out
    }

    /**
     * Relays an unrecognised connection to the real masking domain so a prober
     * sees a genuine TLS server. Mirror of proxy_to_masking_domain().
     */
    fun proxyToMaskingDomain(
        client: SocketStream,
        initialData: ByteArray,
        domain: String,
        label: String,
    ) {
        val upstream = try {
            Tls.connectPlain(domain, 443, 10_000, 16 * 1024)
        } catch (e: Exception) {
            Logger.w("[$label] masking: cannot connect to $domain:443: $e")
            return
        }

        Logger.d("[$label] masking -> $domain:443")
        Stats.connectionsMasked.incrementAndGet()

        val up = SocketStream(upstream, 16 * 1024)
        try {
            if (initialData.isNotEmpty()) {
                up.write(initialData)
                up.flush()
            }

            val t = thread(name = "mask-up-$label") {
                relay(up, client)
            }
            relay(client, up)
            t.join(3_000)
        } catch (_: Exception) {
        } finally {
            runCatching { up.close() }
            runCatching { client.close() }
        }
    }

    private fun relay(src: DataStream, dst: DataStream) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = src.read(buf, 0, buf.size)
                if (n <= 0) break
                dst.write(buf, 0, n)
                dst.flush()
            }
        } catch (_: Exception) {
        } finally {
            runCatching { dst.close() }
        }
    }
}

/**
 * Wraps a client socket so MTProto bytes travel inside TLS 1.3 application
 * data records. Port of fake_tls.py::FakeTlsStream.
 */
class FakeTlsStream(private val inner: SocketStream) : DataStream {

    private var pending = ByteArray(0)
    private var pendingPos = 0
    private var readLeft = 0

    private fun buffered(): Int = pending.size - pendingPos

    override fun readExactly(n: Int): ByteArray {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            if (buffered() == 0) {
                val payload = readTlsPayload()
                if (payload.isEmpty()) throw EOFException("incomplete TLS payload, got $got of $n")
                pending = payload
                pendingPos = 0
            }
            val take = minOf(buffered(), n - got)
            System.arraycopy(pending, pendingPos, out, got, take)
            pendingPos += take
            got += take
        }
        return out
    }

    override fun read(dest: ByteArray, off: Int, len: Int): Int {
        if (buffered() == 0) {
            val payload = readTlsPayload()
            if (payload.isEmpty()) return -1
            pending = payload
            pendingPos = 0
        }
        val n = minOf(buffered(), len)
        System.arraycopy(pending, pendingPos, dest, off, n)
        pendingPos += n
        return n
    }

    private fun readTlsPayload(): ByteArray {
        if (readLeft > 0) {
            val buf = ByteArray(minOf(readLeft, 65536))
            val n = inner.read(buf, 0, buf.size)
            if (n <= 0) return ByteArray(0)
            readLeft -= n
            return if (n == buf.size) buf else buf.copyOf(n)
        }

        while (true) {
            val hdr = try {
                inner.readExactly(5)
            } catch (_: EOFException) {
                return ByteArray(0)
            }
            val rtype = hdr[0].toInt() and 0xFF
            val recLen = ((hdr[3].toInt() and 0xFF) shl 8) or (hdr[4].toInt() and 0xFF)

            if (rtype == FakeTls.TLS_RECORD_CCS) {
                if (recLen > 0) inner.readExactly(recLen)
                continue
            }
            if (rtype != FakeTls.TLS_RECORD_APPDATA) return ByteArray(0)

            val want = minOf(recLen, 65536)
            val buf = ByteArray(want)
            val n = inner.read(buf, 0, want)
            if (n <= 0) return ByteArray(0)
            val remaining = recLen - n
            if (remaining > 0) readLeft = remaining
            return if (n == buf.size) buf else buf.copyOf(n)
        }
    }

    override fun write(data: ByteArray, off: Int, len: Int) {
        inner.write(FakeTls.wrapTlsRecord(data, off, len))
    }

    override fun flush() = inner.flush()

    override fun close() = inner.close()

    override fun setReadTimeout(ms: Int) = inner.setReadTimeout(ms)
}
