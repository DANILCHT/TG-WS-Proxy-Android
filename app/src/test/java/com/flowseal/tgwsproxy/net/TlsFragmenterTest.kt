package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Crypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream

/**
 * The ClientHello split is the main anti-filtering trick, so the parser that
 * locates the SNI is checked against a hand-built handshake as well as the
 * malformed inputs a hostile middlebox could produce.
 */
class TlsFragmenterTest {

    /** Builds a minimal but structurally valid ClientHello for [host]. */
    private fun clientHello(host: String, extraExtBefore: Boolean = false): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)

        val sni = ByteArrayOutputStream().apply {
            // server_name_list
            write16(hostBytes.size + 3)
            write(0) // name_type = host_name
            write16(hostBytes.size)
            write(hostBytes)
        }.toByteArray()

        val extensions = ByteArrayOutputStream().apply {
            if (extraExtBefore) {
                write16(0x000b) // ec_point_formats
                write16(2)
                write(byteArrayOf(1, 0))
            }
            write16(0x0000) // server_name
            write16(sni.size)
            write(sni)
        }.toByteArray()

        val body = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x03, 0x03)) // client_version
            write(ByteArray(32) { 0x11 }) // random
            write(0) // session_id length
            write16(2) // cipher_suites length
            write(byteArrayOf(0x13, 0x01))
            write(1) // compression_methods length
            write(0)
            write16(extensions.size)
            write(extensions)
        }.toByteArray()

        val handshake = ByteArrayOutputStream().apply {
            write(0x01) // client_hello
            write(body.size shr 16 and 0xFF)
            write(body.size shr 8 and 0xFF)
            write(body.size and 0xFF)
            write(body)
        }.toByteArray()

        return ByteArrayOutputStream().apply {
            write(0x16) // handshake record
            write(byteArrayOf(0x03, 0x01))
            write16(handshake.size)
            write(handshake)
        }.toByteArray()
    }

    private fun ByteArrayOutputStream.write16(v: Int) {
        write((v shr 8) and 0xFF)
        write(v and 0xFF)
    }

    @Test
    fun splitLandsInsideTheHostname() {
        val host = "kws2.web.telegram.org"
        val hello = clientHello(host)
        val cut = TlsFragmenter.splitPoint(hello, hello.size)

        val hostStart = indexOf(hello, host.toByteArray(Charsets.US_ASCII))
        assertTrue("hostname not found in the built hello", hostStart >= 0)
        assertTrue(
            "cut $cut outside hostname [$hostStart, ${hostStart + host.length})",
            cut > hostStart && cut < hostStart + host.length,
        )
    }

    @Test
    fun neitherHalfContainsTheWholeHostname() {
        val host = "kws2.web.telegram.org"
        val hello = clientHello(host)
        val cut = TlsFragmenter.splitPoint(hello, hello.size)
        val needle = host.toByteArray(Charsets.US_ASCII)

        assertTrue(indexOf(hello.copyOfRange(0, cut), needle) < 0)
        assertTrue(indexOf(hello.copyOfRange(cut, hello.size), needle) < 0)
    }

    @Test
    fun handlesExtensionsBeforeSni() {
        val host = "example.org"
        val hello = clientHello(host, extraExtBefore = true)
        val cut = TlsFragmenter.splitPoint(hello, hello.size)
        val hostStart = indexOf(hello, host.toByteArray(Charsets.US_ASCII))
        assertTrue(cut > hostStart && cut < hostStart + host.length)
    }

    @Test
    fun nonHandshakeRecordIsNotSplit() {
        val appData = ByteArray(200) { 0x17 }
        assertEquals(-1, TlsFragmenter.splitPoint(appData, appData.size))
    }

    @Test
    fun tinyBufferIsNotSplit() {
        val tiny = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x02, 0x01)
        assertEquals(-1, TlsFragmenter.splitPoint(tiny, tiny.size))
    }

    @Test
    fun helloWithoutSniFallsBackToFixedOffset() {
        val hello = clientHello("a.bc")
        // Corrupt the extension type so SNI cannot be found.
        val sniType = indexOfSniType(hello)
        assertTrue(sniType > 0)
        hello[sniType] = 0x7F
        hello[sniType + 1] = 0x7F

        val cut = TlsFragmenter.splitPoint(hello, hello.size)
        assertEquals(TlsFragmenter.FALLBACK_SPLIT, cut)
    }

    @Test
    fun truncatedHelloDoesNotThrow() {
        val hello = clientHello("kws2.web.telegram.org")
        for (len in 1 until hello.size) {
            // Must never throw regardless of where the buffer ends.
            val cut = TlsFragmenter.splitPoint(hello, len)
            assertTrue("cut=$cut len=$len", cut == -1 || cut in 1 until len)
        }
    }

    @Test
    fun randomGarbageDoesNotThrow() {
        for (i in 0 until 200) {
            val data = Crypto.randomBytes(64 + i)
            data[0] = 0x16
            data[5] = 0x01
            val cut = TlsFragmenter.splitPoint(data, data.size)
            assertTrue(cut == -1 || cut in 1 until data.size)
        }
    }

    // ------------------------------------------------------------ stream tests

    @Test
    fun firstWriteIsSplitAndTheRestIsNot() {
        val sink = RecordingStream()
        val out = FragmentingOutputStream(sink, 0)
        val hello = clientHello("kws2.web.telegram.org")

        out.write(hello, 0, hello.size)
        assertEquals(2, sink.writes.size)
        // TCP segmentation only: the bytes, and so the TLS record, stay as they were.
        assertTrue(sink.writes[0].size + sink.writes[1].size == hello.size)
        assertTrue(sink.data().contentEquals(hello))

        val payload = Crypto.randomBytes(100)
        out.write(payload, 0, payload.size)
        assertEquals(3, sink.writes.size)
    }

    /**
     * A plain HTTP upgrade must leave in one piece: cut inside its Host header
     * it got the whole flow frozen after ~32 KB on a Russian home Wi-Fi.
     */
    @Test
    fun httpRequestGoesOutWhole() {
        val sink = RecordingStream()
        val req = (
            "GET /apiws HTTP/1.1\r\nHost: kws4.example.co.uk\r\nUpgrade: websocket\r\n" +
                "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)
        FragmentingOutputStream(sink, 0).write(req, 0, req.size)
        assertEquals(1, sink.writes.size)
        assertTrue(sink.data().contentEquals(req))
    }

    @Test
    fun nonHandshakeFirstWriteGoesOutWhole() {
        val sink = RecordingStream()
        val out = FragmentingOutputStream(sink, 0)
        val data = ByteArray(300) { 0x17 }
        out.write(data, 0, data.size)
        assertEquals(1, sink.writes.size)
    }

    @Test
    fun offsetWriteIsSplitCorrectly() {
        val hello = clientHello("kws2.web.telegram.org")
        val padded = ByteArray(7) + hello
        val sink = RecordingStream()
        FragmentingOutputStream(sink, 0).write(padded, 7, hello.size)

        assertEquals(2, sink.writes.size)
        assertTrue(sink.data().contentEquals(hello))
    }

    private class RecordingStream : OutputStream() {
        val writes = ArrayList<ByteArray>()
        override fun write(b: Int) {
            writes.add(byteArrayOf(b.toByte()))
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            writes.add(b.copyOfRange(off, off + len))
        }

        fun data(): ByteArray {
            val out = ByteArrayOutputStream()
            for (w in writes) out.write(w)
            return out.toByteArray()
        }
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    /** Offset of the 0x0000 server_name extension type inside [hello]. */
    private fun indexOfSniType(hello: ByteArray): Int {
        // Extensions start after 5 record + 4 handshake + 2 version + 32 random
        // + 1 session + 2+2 ciphers + 1+1 compression + 2 ext length.
        var p = 5 + 4 + 2 + 32
        p += 1 + 0
        p += 2 + 2
        p += 1 + 1
        p += 2
        return p
    }
}
