package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.DataStream
import com.flowseal.tgwsproxy.net.RawWebSocket
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Re-encryption context. Port of bridge.py::CryptoCtx.
 *
 *  - cltDec: decrypt bytes coming from the Telegram client
 *  - cltEnc: encrypt bytes going to the Telegram client
 *  - tgEnc:  encrypt bytes going to Telegram
 *  - tgDec:  decrypt bytes coming from Telegram
 */
class CryptoCtx(
    val cltDec: Crypto.CtrStream,
    val cltEnc: Crypto.CtrStream,
    val tgEnc: Crypto.CtrStream,
    val tgDec: Crypto.CtrStream,
)

/**
 * Splits a TCP stream into individual MTProto transport packets so each one can
 * be sent as its own WebSocket frame. Port of bridge.py::MsgSplitter.
 *
 * It keeps two parallel buffers: the ciphertext that will actually be forwarded
 * and the plaintext used only to read packet lengths.
 */
class MsgSplitter(relayInit: ByteArray, private val proto: Int) {

    private val dec: Crypto.CtrStream = Crypto.CtrStream(
        relayInit.copyOfRange(8, 40),
        relayInit.copyOfRange(40, 56),
    ).also { it.skip(64) }

    private var cipherBuf = ByteArray(0)
    private var plainBuf = ByteArray(0)
    private var disabled = false

    fun split(chunk: ByteArray): List<ByteArray> = split(chunk, 0, chunk.size)

    fun split(chunk: ByteArray, off: Int, len: Int): List<ByteArray> {
        if (len == 0) return emptyList()
        if (disabled) return listOf(chunk.copyOfRange(off, off + len))

        cipherBuf = concat(cipherBuf, chunk, off, len)
        plainBuf = concat(plainBuf, dec.update(chunk, off, len))

        val parts = ArrayList<ByteArray>(4)
        var offset = 0
        val bufLen = cipherBuf.size
        while (offset < bufLen) {
            val packetLen = nextPacketLen(offset, bufLen - offset) ?: break
            if (packetLen <= 0) {
                parts.add(cipherBuf.copyOfRange(offset, bufLen))
                offset = bufLen
                disabled = true
                break
            }
            parts.add(cipherBuf.copyOfRange(offset, offset + packetLen))
            offset += packetLen
        }

        if (offset > 0) {
            cipherBuf = cipherBuf.copyOfRange(offset, cipherBuf.size)
            plainBuf = plainBuf.copyOfRange(offset, plainBuf.size)
        }
        return parts
    }

    fun flush(): List<ByteArray> {
        if (cipherBuf.isEmpty()) return emptyList()
        val tail = cipherBuf
        cipherBuf = ByteArray(0)
        plainBuf = ByteArray(0)
        return listOf(tail)
    }

    /** null = need more bytes, 0 = give up and pass through, >0 = packet size. */
    private fun nextPacketLen(offset: Int, avail: Int): Int? {
        if (avail <= 0) return null
        return when (proto) {
            Const.PROTO_ABRIDGED_INT -> nextAbridgedLen(offset, avail)
            Const.PROTO_INTERMEDIATE_INT,
            Const.PROTO_PADDED_INTERMEDIATE_INT -> nextIntermediateLen(offset, avail)
            else -> 0
        }
    }

    private fun nextAbridgedLen(offset: Int, avail: Int): Int? {
        val first = plainBuf[offset].toInt() and 0xFF
        val payloadLen: Int
        val headerLen: Int
        if (first == 0x7F || first == 0xFF) {
            if (avail < 4) return null
            payloadLen = (((plainBuf[offset + 1].toInt() and 0xFF)) or
                ((plainBuf[offset + 2].toInt() and 0xFF) shl 8) or
                ((plainBuf[offset + 3].toInt() and 0xFF) shl 16)) * 4
            headerLen = 4
        } else {
            payloadLen = (first and 0x7F) * 4
            headerLen = 1
        }
        if (payloadLen <= 0) return 0
        val packetLen = headerLen + payloadLen
        if (avail < packetLen) return null
        return packetLen
    }

    private fun nextIntermediateLen(offset: Int, avail: Int): Int? {
        if (avail < 4) return null
        var v = 0L
        for (i in 0 until 4) {
            v = v or ((plainBuf[offset + i].toLong() and 0xFF) shl (8 * i))
        }
        val payloadLen = (v and 0x7FFFFFFFL).toInt()
        if (payloadLen <= 0) return 0
        val packetLen = 4 + payloadLen
        if (avail < packetLen) return null
        return packetLen
    }

    private fun concat(a: ByteArray, b: ByteArray): ByteArray = concat(a, b, 0, b.size)

    private fun concat(a: ByteArray, b: ByteArray, off: Int, len: Int): ByteArray {
        if (a.isEmpty()) return b.copyOfRange(off, off + len)
        val out = ByteArray(a.size + len)
        System.arraycopy(a, 0, out, 0, a.size)
        System.arraycopy(b, off, out, a.size, len)
        return out
    }
}

/**
 * Bidirectional relay with re-encryption between the local client socket and an
 * upstream transport. Port of bridge.py::bridge_ws_reencrypt /
 * _bridge_tcp_reencrypt.
 *
 * The downstream direction runs on a helper thread, the upstream direction on
 * the calling thread; the call returns once either side finishes.
 */
object Bridge {

    private const val CHUNK = 65536

    fun bridgeWsReencrypt(
        client: DataStream,
        ws: RawWebSocket,
        label: String,
        ctx: CryptoCtx,
        dc: Int?,
        isMedia: Boolean,
        splitter: MsgSplitter?,
    ) {
        val dcTag = if (dc != null) "DC$dc${if (isMedia) "m" else ""}" else "DC?"

        val upBytes = AtomicLong()
        val downBytes = AtomicLong()
        val upPackets = AtomicLong()
        val downPackets = AtomicLong()
        val reason = AtomicReference("normal")
        val startTime = System.nanoTime()

        val downThread = Thread({
            try {
                while (true) {
                    val data = ws.recv()
                    if (data == null) {
                        reason.compareAndSet("normal", "upstream: ws_close")
                        break
                    }
                    Stats.bytesDown.addAndGet(data.size.toLong())
                    downBytes.addAndGet(data.size.toLong())
                    downPackets.incrementAndGet()
                    val plain = ctx.tgDec.update(data)
                    client.write(ctx.cltEnc.update(plain))
                    client.flush()
                }
            } catch (e: java.net.SocketTimeoutException) {
                reason.compareAndSet("normal", "upstream: timeout")
            } catch (e: java.io.EOFException) {
                reason.compareAndSet("normal", "upstream: tcp_reset")
            } catch (e: Exception) {
                reason.compareAndSet("normal", "upstream: ${e.javaClass.simpleName}")
                Logger.d("[$label] ws->tcp ended: $e")
            } finally {
                runCatching { client.close() }
            }
        }, "ws-down")
        downThread.isDaemon = true
        downThread.start()

        val buf = ByteArray(CHUNK)
        try {
            while (true) {
                val n = client.read(buf, 0, CHUNK)
                if (n <= 0) {
                    if (splitter != null) {
                        val tail = splitter.flush()
                        if (tail.isNotEmpty()) ws.send(tail[0])
                    }
                    break
                }
                Stats.bytesUp.addAndGet(n.toLong())
                upBytes.addAndGet(n.toLong())
                upPackets.incrementAndGet()
                val plain = ctx.cltDec.update(buf, 0, n)
                val enc = ctx.tgEnc.update(plain)
                if (splitter != null) {
                    val parts = splitter.split(enc)
                    if (parts.isEmpty()) continue
                    if (parts.size > 1) ws.sendBatch(parts) else ws.send(parts[0])
                } else {
                    ws.send(enc)
                }
            }
        } catch (e: java.io.EOFException) {
            reason.compareAndSet("normal", "client: eof")
        } catch (e: Exception) {
            reason.compareAndSet("normal", "client: ${e.javaClass.simpleName}")
            Logger.d("[$label] tcp->ws ended: $e")
        } finally {
            runCatching { ws.close() }
            runCatching { client.close() }
            downThread.join(2_000)
            val elapsed = (System.nanoTime() - startTime) / 1_000_000_000.0
            Logger.i(
                "[$label] $dcTag WS session closed (${reason.get()}): " +
                    "^${Const.humanBytes(upBytes.get())} (${upPackets.get()} pkts) " +
                    "v${Const.humanBytes(downBytes.get())} (${downPackets.get()} pkts) " +
                    String.format(java.util.Locale.US, "in %.1fs", elapsed)
            )
        }
    }

    fun bridgeTcpReencrypt(
        client: DataStream,
        remote: DataStream,
        label: String,
        ctx: CryptoCtx,
    ) {
        val downThread = Thread({
            val buf = ByteArray(CHUNK)
            try {
                while (true) {
                    val n = remote.read(buf, 0, CHUNK)
                    if (n <= 0) break
                    Stats.bytesDown.addAndGet(n.toLong())
                    val plain = ctx.tgDec.update(buf, 0, n)
                    client.write(ctx.cltEnc.update(plain))
                    client.flush()
                }
            } catch (e: Exception) {
                Logger.d("[$label] tcp forward (down) ended: $e")
            } finally {
                runCatching { client.close() }
            }
        }, "tcp-down")
        downThread.isDaemon = true
        downThread.start()

        val buf = ByteArray(CHUNK)
        try {
            while (true) {
                val n = client.read(buf, 0, CHUNK)
                if (n <= 0) break
                Stats.bytesUp.addAndGet(n.toLong())
                val plain = ctx.cltDec.update(buf, 0, n)
                remote.write(ctx.tgEnc.update(plain))
                remote.flush()
            }
        } catch (e: Exception) {
            Logger.d("[$label] tcp forward (up) ended: $e")
        } finally {
            runCatching { remote.close() }
            runCatching { client.close() }
            downThread.join(2_000)
        }
    }
}
