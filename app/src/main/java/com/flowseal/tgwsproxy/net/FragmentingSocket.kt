package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Logger
import java.io.OutputStream
import java.net.Socket

/**
 * A [Socket] whose first write is split across two TCP segments.
 *
 * `SSLSocketFactory.createSocket(underlying, ...)` writes the ClientHello to
 * `underlying.getOutputStream()`, so overriding that stream is the only seam
 * available for fragmenting the handshake without hand-rolling TLS.
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
 * Splits the first buffer it is handed at a point inside the TLS SNI, flushing
 * between the halves so they leave as separate packets.
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

        val cut = TlsFragmenter.splitPoint(
            if (off == 0) b else b.copyOfRange(off, off + len),
            len,
        )
        if (cut <= 0 || cut >= len) {
            inner.write(b, off, len)
            return
        }

        inner.write(b, off, cut)
        inner.flush()
        if (delayMs > 0) {
            runCatching { Thread.sleep(delayMs) }
        }
        inner.write(b, off + cut, len - cut)
        inner.flush()
        Logger.d("ClientHello split at $cut/$len bytes")
    }

    override fun write(b: ByteArray) = write(b, 0, b.size)

    override fun flush() = inner.flush()

    override fun close() = inner.close()
}
