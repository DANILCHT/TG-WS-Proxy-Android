package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Const
import com.flowseal.tgwsproxy.core.Crypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks the RFC 6455 frame encoding used to talk to Telegram's web endpoints.
 * A wrong length field or an unmasked client frame gets the connection dropped
 * by the server, so the three length forms are covered explicitly.
 */
class WsFramingTest {

    private val mask = byteArrayOf(0x11, 0x22, 0x33, 0x44)

    private fun frame(payload: ByteArray, masked: Boolean = true): ByteArray =
        WsFraming.buildFrame(
            RawWebSocket.OP_BINARY, payload, 0, payload.size, masked, mask,
        )

    @Test
    fun shortMaskedFrameUsesSevenBitLength() {
        val payload = ByteArray(10) { it.toByte() }
        val f = frame(payload)

        assertEquals(0x82, f[0].toInt() and 0xFF) // FIN + binary
        assertEquals(0x80 or 10, f[1].toInt() and 0xFF) // MASK + length
        assertTrue(f.copyOfRange(2, 6).contentEquals(mask))
        assertEquals(6 + payload.size, f.size)

        val unmasked = ByteArray(payload.size)
        WsFraming.xorMaskInto(f, 6, payload.size, mask, unmasked, 0)
        assertTrue(unmasked.contentEquals(payload))
    }

    @Test
    fun mediumFrameUsesSixteenBitLength() {
        val payload = Crypto.randomBytes(1000)
        val f = frame(payload)

        assertEquals(0x80 or 126, f[1].toInt() and 0xFF)
        val declared = ((f[2].toInt() and 0xFF) shl 8) or (f[3].toInt() and 0xFF)
        assertEquals(1000, declared)
        assertEquals(8 + payload.size, f.size)

        val unmasked = ByteArray(payload.size)
        WsFraming.xorMaskInto(f, 8, payload.size, mask, unmasked, 0)
        assertTrue(unmasked.contentEquals(payload))
    }

    @Test
    fun largeFrameUsesSixtyFourBitLength() {
        val payload = Crypto.randomBytes(70_000)
        val f = frame(payload)

        assertEquals(0x80 or 127, f[1].toInt() and 0xFF)
        var declared = 0L
        for (i in 0 until 8) declared = (declared shl 8) or (f[2 + i].toLong() and 0xFF)
        assertEquals(70_000L, declared)
        assertEquals(14 + payload.size, f.size)
    }

    @Test
    fun boundaryLengthsPickTheRightHeaderForm() {
        assertEquals(0x80 or 125, frame(ByteArray(125))[1].toInt() and 0xFF)
        assertEquals(0x80 or 126, frame(ByteArray(126))[1].toInt() and 0xFF)
        assertEquals(0x80 or 126, frame(ByteArray(65535))[1].toInt() and 0xFF)
        assertEquals(0x80 or 127, frame(ByteArray(65536))[1].toInt() and 0xFF)
    }

    @Test
    fun clientFramesAreAlwaysMasked() {
        // Telegram closes unmasked client frames; the mask bit must be set.
        val f = frame(ByteArray(4))
        assertTrue((f[1].toInt() and 0x80) != 0)

        val server = frame(ByteArray(4), masked = false)
        assertFalse((server[1].toInt() and 0x80) != 0)
        assertEquals(2 + 4, server.size)
    }

    @Test
    fun emptyPayloadProducesHeaderOnly() {
        val f = frame(ByteArray(0))
        assertEquals(6, f.size)
        assertEquals(0x80, f[1].toInt() and 0xFF)
    }

    @Test
    fun maskingIsItsOwnInverse() {
        val data = Crypto.randomBytes(300)
        val once = ByteArray(data.size)
        WsFraming.xorMaskInto(data, 0, data.size, mask, once, 0)
        val twice = ByteArray(data.size)
        WsFraming.xorMaskInto(once, 0, once.size, mask, twice, 0)
        assertTrue(twice.contentEquals(data))
    }

    @Test
    fun relayInitFitsInASingleShortFrame() {
        // The 64-byte MTProto init must go out as one frame.
        val f = frame(ByteArray(Const.HANDSHAKE_LEN))
        assertEquals(0x80 or 64, f[1].toInt() and 0xFF)
        assertEquals(6 + 64, f.size)
    }

    @Test
    fun base64KeyMatchesRfc4648() {
        assertEquals("", Crypto.base64(ByteArray(0)))
        assertEquals("Zg==", Crypto.base64("f".toByteArray()))
        assertEquals("Zm8=", Crypto.base64("fo".toByteArray()))
        assertEquals("Zm9v", Crypto.base64("foo".toByteArray()))
        assertEquals("Zm9vYmFy", Crypto.base64("foobar".toByteArray()))
        // Sec-WebSocket-Key is 16 random bytes => 24 chars with one pad.
        assertEquals(24, Crypto.base64(Crypto.randomBytes(16)).length)
    }
}
