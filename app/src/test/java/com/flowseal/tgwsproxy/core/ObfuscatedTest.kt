package com.flowseal.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the obfuscated MTProto handshake: what the client sends must be parsed
 * back to the same DC and protocol, and the four derived CTR streams must form
 * matching encrypt/decrypt pairs.
 */
class ObfuscatedTest {

    private val secret = Const.fromHex("00112233445566778899aabbccddeeff")

    @Test
    fun parsesDcAndProtocolFromAClientInit() {
        for (tag in listOf(
            Const.PROTO_TAG_ABRIDGED,
            Const.PROTO_TAG_INTERMEDIATE,
            Const.PROTO_TAG_SECURE,
        )) {
            val init = Obfuscated.buildClientInit(secret, tag, 2)
            val parsed = Obfuscated.tryHandshake(init, secret)
            assertNotNull(parsed)
            assertEquals(2, parsed!!.dcId)
            assertFalse(parsed.isMedia)
            assertTrue(parsed.protoTag.contentEquals(tag))
        }
    }

    @Test
    fun negativeDcIndexMeansMedia() {
        val init = Obfuscated.buildClientInit(secret, Const.PROTO_TAG_ABRIDGED, -4)
        val parsed = Obfuscated.tryHandshake(init, secret)
        assertNotNull(parsed)
        assertEquals(4, parsed!!.dcId)
        assertTrue(parsed.isMedia)
    }

    @Test
    fun testDcIndexSurvivesTheRoundTrip() {
        val init = Obfuscated.buildClientInit(secret, Const.PROTO_TAG_INTERMEDIATE, 10002)
        val parsed = Obfuscated.tryHandshake(init, secret)
        assertNotNull(parsed)
        assertEquals(10002, parsed!!.dcId)
    }

    @Test
    fun rejectsAWrongSecret() {
        val init = Obfuscated.buildClientInit(secret, Const.PROTO_TAG_ABRIDGED, 2)
        val other = Const.fromHex("ffeeddccbbaa99887766554433221100")
        assertNull(Obfuscated.tryHandshake(init, other))
    }

    @Test
    fun rejectsRandomBytes() {
        // A random init decrypts to a random proto tag; over many attempts none
        // should be accepted.
        var accepted = 0
        for (i in 0 until 200) {
            if (Obfuscated.tryHandshake(Crypto.randomBytes(64), secret) != null) accepted++
        }
        assertEquals(0, accepted)
    }

    @Test
    fun relayInitAvoidsReservedPrefixes() {
        for (i in 0 until 300) {
            val init = Obfuscated.generateRelayInit(Const.PROTO_TAG_ABRIDGED, 2)
            assertEquals(64, init.size)
            assertFalse((init[0].toInt() and 0xFF) in Const.RESERVED_FIRST_BYTES)
            for (bad in Const.RESERVED_STARTS) {
                assertFalse(Const.startsWith(init, bad))
            }
            assertFalse(Const.regionEquals(init, 4, Const.RESERVED_CONTINUE))
        }
    }

    @Test
    fun relayInitEncodesProtocolAndDcForTheUpstream() {
        val dcIdx = -3
        val init = Obfuscated.generateRelayInit(Const.PROTO_TAG_INTERMEDIATE, dcIdx)

        // The upstream decrypts with the raw key (no secret hash).
        val key = init.copyOfRange(8, 40)
        val iv = init.copyOfRange(40, 56)
        val decrypted = Crypto.CtrStream(key, iv).update(init)

        assertTrue(
            decrypted.copyOfRange(56, 60).contentEquals(Const.PROTO_TAG_INTERMEDIATE)
        )
        var parsedDc = (decrypted[60].toInt() and 0xFF) or
            ((decrypted[61].toInt() and 0xFF) shl 8)
        if (parsedDc >= 0x8000) parsedDc -= 0x10000
        assertEquals(dcIdx, parsedDc)
    }

    @Test
    fun cryptoCtxFormsMatchingStreamPairs() {
        val clientInit = Obfuscated.buildClientInit(secret, Const.PROTO_TAG_ABRIDGED, 2)
        val parsed = Obfuscated.tryHandshake(clientInit, secret)!!
        val relayInit = Obfuscated.generateRelayInit(parsed.protoTag, 2)
        val ctx = Obfuscated.buildCryptoCtx(parsed.decPrekeyAndIv, secret, relayInit)

        // Client -> proxy: the client's encryptor is the proxy's cltDec.
        val clientPrekey = parsed.decPrekeyAndIv.copyOfRange(0, 32)
        val clientIv = parsed.decPrekeyAndIv.copyOfRange(32, 48)
        val clientEnc = Crypto.CtrStream(Crypto.sha256(clientPrekey, secret), clientIv)
        clientEnc.skip(64) // the client also skips its own init

        val payload = "hello telegram".toByteArray()
        val onWire = clientEnc.update(payload)
        assertTrue(ctx.cltDec.update(onWire).contentEquals(payload))

        // Proxy -> client: the client's decryptor mirrors cltEnc.
        val reversed = Crypto.reversed(parsed.decPrekeyAndIv)
        val clientDec = Crypto.CtrStream(
            Crypto.sha256(reversed.copyOfRange(0, 32), secret),
            reversed.copyOfRange(32, 48),
        )
        val down = "response".toByteArray()
        val encDown = ctx.cltEnc.update(down)
        assertTrue(clientDec.update(encDown).contentEquals(down))

        // Proxy -> Telegram and back: tgEnc pairs with the upstream decryptor.
        val upstreamDec = Crypto.CtrStream(
            relayInit.copyOfRange(8, 40), relayInit.copyOfRange(40, 56),
        )
        upstreamDec.skip(64)
        val up = "to dc".toByteArray()
        assertTrue(upstreamDec.update(ctx.tgEnc.update(up)).contentEquals(up))

        val relayReversed = Crypto.reversed(relayInit.copyOfRange(8, 56))
        val upstreamEnc = Crypto.CtrStream(
            relayReversed.copyOfRange(0, 32), relayReversed.copyOfRange(32, 48),
        )
        val fromDc = "from dc".toByteArray()
        assertTrue(ctx.tgDec.update(upstreamEnc.update(fromDc)).contentEquals(fromDc))
    }

    @Test
    fun protoIntMapsTagsLikePython() {
        assertEquals(Const.PROTO_ABRIDGED_INT, Obfuscated.protoInt(Const.PROTO_TAG_ABRIDGED))
        assertEquals(
            Const.PROTO_INTERMEDIATE_INT, Obfuscated.protoInt(Const.PROTO_TAG_INTERMEDIATE),
        )
        assertEquals(
            Const.PROTO_PADDED_INTERMEDIATE_INT, Obfuscated.protoInt(Const.PROTO_TAG_SECURE),
        )
    }
}
