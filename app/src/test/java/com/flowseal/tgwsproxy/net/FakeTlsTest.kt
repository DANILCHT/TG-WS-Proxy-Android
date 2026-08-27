package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Const
import com.flowseal.tgwsproxy.core.Crypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kotlin port of tests/test_fake_tls.py. */
class FakeTlsTest {

    private val secret = Const.fromHex("00112233445566778899aabbccddeeff")

    private val clientRandomOffset = 11
    private val clientRandomLen = 32
    private val sessionIdOffset = 44
    private val sessionIdLen = 32

    private fun clientHello(
        secret: ByteArray = this.secret,
        timestamp: Long = System.currentTimeMillis() / 1000,
        sessionId: ByteArray = Crypto.randomBytes(32),
    ): ByteArray {
        val body = ByteArray(517)
        body[0] = FakeTls.TLS_RECORD_HANDSHAKE.toByte()
        body[1] = 0x03
        body[2] = 0x01
        val recLen = body.size - 5
        body[3] = ((recLen shr 8) and 0xFF).toByte()
        body[4] = (recLen and 0xFF).toByte()
        body[5] = 0x01
        body[43] = 0x20
        System.arraycopy(sessionId, 0, body, sessionIdOffset, sessionIdLen)

        val digest = Crypto.hmacSha256(secret, body)
        val clientRandom = digest.copyOfRange(0, clientRandomLen)
        for (i in 0 until 4) {
            val tsByte = ((timestamp shr (8 * i)) and 0xFF).toInt()
            clientRandom[28 + i] = (digest[28 + i].toInt() xor tsByte).toByte()
        }
        System.arraycopy(clientRandom, 0, body, clientRandomOffset, clientRandomLen)
        return body
    }

    @Test
    fun acceptsWellFormedHello() {
        val sessionId = Crypto.randomBytes(32)
        val now = System.currentTimeMillis() / 1000
        val result = FakeTls.verifyClientHello(
            clientHello(timestamp = now, sessionId = sessionId), secret,
        )
        assertNotNull(result)
        assertEquals(clientRandomLen, result!!.clientRandom.size)
        assertTrue(result.sessionId.contentEquals(sessionId))
        assertEquals(now, result.timestamp)
    }

    @Test
    fun rejectsWrongSecret() {
        val other = Const.fromHex("ffeeddccbbaa99887766554433221100")
        assertNull(FakeTls.verifyClientHello(clientHello(), other))
    }

    @Test
    fun rejectsStaleTimestamp() {
        val stale = System.currentTimeMillis() / 1000 - 3600
        assertNull(FakeTls.verifyClientHello(clientHello(timestamp = stale), secret))
    }

    @Test
    fun rejectsTamperedBody() {
        val hello = clientHello()
        hello[300] = (hello[300].toInt() xor 0xFF).toByte()
        assertNull(FakeTls.verifyClientHello(hello, secret))
    }

    @Test
    fun rejectsShortAndNonHandshakeRecords() {
        assertNull(
            FakeTls.verifyClientHello(
                byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x10), secret,
            )
        )
        val nonHandshake = clientHello()
        nonHandshake[0] = 0x17
        assertNull(FakeTls.verifyClientHello(nonHandshake, secret))

        val notClientHello = clientHello()
        notClientHello[5] = 0x02
        assertNull(FakeTls.verifyClientHello(notClientHello, secret))
    }

    @Test
    fun serverHelloEchoesSessionIdAndBindsClientRandom() {
        val sessionId = Crypto.randomBytes(32)
        val clientRandom = Crypto.randomBytes(32)
        val response = FakeTls.buildServerHello(secret, clientRandom, sessionId)

        assertEquals(FakeTls.TLS_RECORD_HANDSHAKE, response[0].toInt() and 0xFF)
        assertTrue(
            response.copyOfRange(sessionIdOffset, sessionIdOffset + sessionIdLen)
                .contentEquals(sessionId)
        )

        val zeroed = response.copyOf()
        java.util.Arrays.fill(zeroed, 11, 11 + 32, 0)
        val expected = Crypto.hmacSha256(secret, clientRandom + zeroed)
        assertTrue(response.copyOfRange(11, 11 + 32).contentEquals(expected))
    }

    @Test
    fun serverHelloPaddingVariesBetweenCalls() {
        val sizes = (0 until 20).map {
            FakeTls.buildServerHello(secret, Crypto.randomBytes(32), Crypto.randomBytes(32)).size
        }.toSet()
        assertTrue(sizes.size > 1)
    }

    @Test
    fun shortPayloadBecomesOneRecord() {
        val payload = "hello".toByteArray()
        val wrapped = FakeTls.wrapTlsRecord(payload, 0, payload.size)
        val expected = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x05) + payload
        assertTrue(wrapped.contentEquals(expected))
    }

    @Test
    fun longPayloadIsChunkedToRecordLimit() {
        val payload = Crypto.randomBytes(FakeTls.TLS_APPDATA_MAX + 100)
        val wrapped = FakeTls.wrapTlsRecord(payload, 0, payload.size)

        var offset = 0
        val chunks = ArrayList<ByteArray>()
        while (offset < wrapped.size) {
            val length = ((wrapped[offset + 3].toInt() and 0xFF) shl 8) or
                (wrapped[offset + 4].toInt() and 0xFF)
            assertTrue(length <= FakeTls.TLS_APPDATA_MAX)
            chunks.add(wrapped.copyOfRange(offset + 5, offset + 5 + length))
            offset += 5 + length
        }
        assertEquals(2, chunks.size)
        var joined = ByteArray(0)
        for (c in chunks) joined += c
        assertTrue(joined.contentEquals(payload))
    }

    @Test
    fun emptyPayloadProducesNoRecords() {
        assertEquals(0, FakeTls.wrapTlsRecord(ByteArray(0), 0, 0).size)
    }
}
