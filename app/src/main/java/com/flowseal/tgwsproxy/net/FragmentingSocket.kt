package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Logger
import java.io.OutputStream
import java.net.Socket

/**
 * A [Socket] whose first write is split so the destination name never sits
 * whole in one packet.
 *
 * `SSLSocketFactory.createSocket(underlying, ...)` writes the ClientHello to
 * `underlying.getOutputStream()`, so overriding that stream is the only seam
 * available for fragmenting the handshake without hand-rolling TLS. Plain
 * ws:// connections write their HTTP upgrade request through the same stream.
 *
 * Only the very first write is touched; everything after it goes straight
 * through, so throughput is unaffected.
 */
class FragmentingSocket(
    private val delayMs: Long = 0L,
) : Socket() {

    private var wrapped: OutputStream? = null

    override fun getOutputStream(): OutputStream {
        wrapped?.let { return it }
        val out = FragmentingOutputStream(super.getOutputStream(), delayMs)
        wrapped = out
        return out
    }
}

/**
 * Splits the first buffer it is handed:
 *  - a TLS ClientHello becomes two TLS records cut in the middle of the SNI,
 *    each sent in its own TCP segment;
 *  - an HTTP request is cut in the middle of the Host header value.
 * Anything else is written unchanged.
 */
internal class FragmentingOutputStream(
    private val inner: OutputStream,
    private val delayMs: Long,
) : OutputStream() {

    private var firstWriteDone = false

    override fun write(b: Int) {
        firstWriteDone = true
        inner.write(b)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (firstWriteDone) {
            inner.write(b, off, len)
            return
        }
        firstWriteDone = true

        val data = if (off == 0 && len == b.size) b else b.copyOfRange(off, off + len)

        val tlsCut = TlsFragmenter.splitPoint(data, len)
        if (tlsCut in 1 until len) {
            val records = TlsFragmenter.splitIntoRecords(data, len, tlsCut)
            if (records != null) {
                sendInTwo(records.first, 0, records.first.size, records.second, 0, records.second.size)
                Logger.d("ClientHello split into two TLS records at $tlsCut/$len bytes")
            } else {
                sendInTwo(data, 0, tlsCut, data, tlsCut, len - tlsCut)
                Logger.d("ClientHello split at $tlsCut/$len bytes")
            }
            return
        }

        val httpCut = TlsFragmenter.httpSplitPoint(data, len)
        if (httpCut in 1 until len) {
            sendInTwo(data, 0, httpCut, data, httpCut, len - httpCut)
            Logger.d("HTTP request split inside Host at $httpCut/$len bytes")
            return
        }

        inner.write(b, off, len)
    }

    private fun sendInTwo(a: ByteArray, aOff: Int, aLen: Int, c: ByteArray, cOff: Int, cLen: Int) {
        inner.write(a, aOff, aLen)
        inner.flush()
        if (delayMs > 0) {
            runCatching { Thread.sleep(delayMs) }
        }
        inner.write(c, cOff, cLen)
        inner.flush()
    }

    override fun write(b: ByteArray) = write(b, 0, b.size)

    override fun flush() = inner.flush()

    override fun close() = inner.close()
}
