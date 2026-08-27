package com.flowseal.tgwsproxy.core

/**
 * MTProto obfuscated-transport handshake handling, extracted from
 * proxy/tg_ws_proxy.py (`_try_handshake`, `_generate_relay_init`,
 * `_build_crypto_ctx`) so it can be unit-tested without a socket.
 */
object Obfuscated {

    class ClientHandshake(
        val dcId: Int,
        val isMedia: Boolean,
        val protoTag: ByteArray,
        val decPrekeyAndIv: ByteArray,
    )

    /**
     * Validates the 64-byte obfuscated init sent by the client and extracts the
     * requested datacenter. Returns null when the secret or protocol tag does
     * not match.
     */
    fun tryHandshake(handshake: ByteArray, secret: ByteArray): ClientHandshake? {
        val decPrekeyAndIv = handshake.copyOfRange(
            Const.SKIP_LEN, Const.SKIP_LEN + Const.PREKEY_LEN + Const.IV_LEN,
        )
        val decPrekey = decPrekeyAndIv.copyOfRange(0, Const.PREKEY_LEN)
        val decIv = decPrekeyAndIv.copyOfRange(Const.PREKEY_LEN, decPrekeyAndIv.size)

        val decKey = Crypto.sha256(decPrekey, secret)
        val decrypted = Crypto.CtrStream(decKey, decIv).update(handshake)

        val protoTag = decrypted.copyOfRange(Const.PROTO_TAG_POS, Const.PROTO_TAG_POS + 4)
        val known = protoTag.contentEquals(Const.PROTO_TAG_ABRIDGED) ||
            protoTag.contentEquals(Const.PROTO_TAG_INTERMEDIATE) ||
            protoTag.contentEquals(Const.PROTO_TAG_SECURE)
        if (!known) return null

        // signed little-endian int16
        var dcIdx = (decrypted[Const.DC_IDX_POS].toInt() and 0xFF) or
            ((decrypted[Const.DC_IDX_POS + 1].toInt() and 0xFF) shl 8)
        if (dcIdx >= 0x8000) dcIdx -= 0x10000

        return ClientHandshake(
            dcId = Math.abs(dcIdx),
            isMedia = dcIdx < 0,
            protoTag = protoTag,
            decPrekeyAndIv = decPrekeyAndIv,
        )
    }

    /**
     * Builds the random 64-byte init header sent upstream. Bytes that would make
     * the stream look like HTTP, TLS or a known MTProto tag are rejected, mirror
     * of `_generate_relay_init`.
     */
    fun generateRelayInit(protoTag: ByteArray, dcIdx: Int): ByteArray {
        var rnd: ByteArray
        while (true) {
            rnd = Crypto.randomBytes(Const.HANDSHAKE_LEN)
            if ((rnd[0].toInt() and 0xFF) in Const.RESERVED_FIRST_BYTES) continue
            if (Const.RESERVED_STARTS.any { Const.startsWith(rnd, it) }) continue
            if (Const.regionEquals(rnd, 4, Const.RESERVED_CONTINUE)) continue
            break
        }

        val encKey = rnd.copyOfRange(Const.SKIP_LEN, Const.SKIP_LEN + Const.PREKEY_LEN)
        val encIv = rnd.copyOfRange(
            Const.SKIP_LEN + Const.PREKEY_LEN,
            Const.SKIP_LEN + Const.PREKEY_LEN + Const.IV_LEN,
        )

        val tailPlain = ByteArray(8)
        System.arraycopy(protoTag, 0, tailPlain, 0, 4)
        tailPlain[4] = (dcIdx and 0xFF).toByte()
        tailPlain[5] = ((dcIdx shr 8) and 0xFF).toByte()
        val extra = Crypto.randomBytes(2)
        tailPlain[6] = extra[0]
        tailPlain[7] = extra[1]

        val encryptedFull = Crypto.CtrStream(encKey, encIv).update(rnd)
        val result = rnd.copyOf()
        for (i in 0 until 8) {
            val keystream = encryptedFull[56 + i].toInt() xor rnd[56 + i].toInt()
            result[Const.PROTO_TAG_POS + i] = (tailPlain[i].toInt() xor keystream).toByte()
        }
        return result
    }

    /**
     * Derives the four CTR streams used for re-encryption between the client and
     * Telegram, mirror of `_build_crypto_ctx`.
     */
    fun buildCryptoCtx(
        clientDecPrekeyIv: ByteArray,
        secret: ByteArray,
        relayInit: ByteArray,
    ): CryptoCtx {
        // key = SHA256(prekey + secret), iv from the handshake
        val cltDecPrekey = clientDecPrekeyIv.copyOfRange(0, Const.PREKEY_LEN)
        val cltDecIv = clientDecPrekeyIv.copyOfRange(Const.PREKEY_LEN, clientDecPrekeyIv.size)
        val cltDecKey = Crypto.sha256(cltDecPrekey, secret)

        val cltEncPrekeyIv = Crypto.reversed(clientDecPrekeyIv)
        val cltEncKey = Crypto.sha256(cltEncPrekeyIv.copyOfRange(0, Const.PREKEY_LEN), secret)
        val cltEncIv = cltEncPrekeyIv.copyOfRange(Const.PREKEY_LEN, cltEncPrekeyIv.size)

        val cltDecryptor = Crypto.CtrStream(cltDecKey, cltDecIv)
        val cltEncryptor = Crypto.CtrStream(cltEncKey, cltEncIv)

        // fast-forward the client decryptor past the 64-byte init
        cltDecryptor.skip(64)

        // relay side: standard obfuscation (no secret hash, raw key)
        val relayEncKey = relayInit.copyOfRange(Const.SKIP_LEN, Const.SKIP_LEN + Const.PREKEY_LEN)
        val relayEncIv = relayInit.copyOfRange(
            Const.SKIP_LEN + Const.PREKEY_LEN,
            Const.SKIP_LEN + Const.PREKEY_LEN + Const.IV_LEN,
        )

        val relayDecPrekeyIv = Crypto.reversed(
            relayInit.copyOfRange(
                Const.SKIP_LEN, Const.SKIP_LEN + Const.PREKEY_LEN + Const.IV_LEN,
            )
        )
        val relayDecKey = relayDecPrekeyIv.copyOfRange(0, Const.KEY_LEN)
        val relayDecIv = relayDecPrekeyIv.copyOfRange(Const.KEY_LEN, relayDecPrekeyIv.size)

        val tgEncryptor = Crypto.CtrStream(relayEncKey, relayEncIv)
        val tgDecryptor = Crypto.CtrStream(relayDecKey, relayDecIv)

        tgEncryptor.skip(64)

        return CryptoCtx(cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor)
    }

    /** Maps a protocol tag to the integer form used by [MsgSplitter]. */
    fun protoInt(protoTag: ByteArray): Int = when {
        protoTag.contentEquals(Const.PROTO_TAG_ABRIDGED) -> Const.PROTO_ABRIDGED_INT
        protoTag.contentEquals(Const.PROTO_TAG_INTERMEDIATE) -> Const.PROTO_INTERMEDIATE_INT
        else -> Const.PROTO_PADDED_INTERMEDIATE_INT
    }

    /**
     * Builds a client init header the way Telegram Desktop does. Used by tests
     * and useful for local diagnostics.
     */
    fun buildClientInit(secret: ByteArray, protoTag: ByteArray, dcIdx: Int): ByteArray {
        var rnd: ByteArray
        while (true) {
            rnd = Crypto.randomBytes(Const.HANDSHAKE_LEN)
            if ((rnd[0].toInt() and 0xFF) in Const.RESERVED_FIRST_BYTES) continue
            if (Const.RESERVED_STARTS.any { Const.startsWith(rnd, it) }) continue
            if (Const.regionEquals(rnd, 4, Const.RESERVED_CONTINUE)) continue
            break
        }

        val prekey = rnd.copyOfRange(Const.SKIP_LEN, Const.SKIP_LEN + Const.PREKEY_LEN)
        val iv = rnd.copyOfRange(
            Const.SKIP_LEN + Const.PREKEY_LEN,
            Const.SKIP_LEN + Const.PREKEY_LEN + Const.IV_LEN,
        )
        val key = Crypto.sha256(prekey, secret)

        val tailPlain = ByteArray(8)
        System.arraycopy(protoTag, 0, tailPlain, 0, 4)
        tailPlain[4] = (dcIdx and 0xFF).toByte()
        tailPlain[5] = ((dcIdx shr 8) and 0xFF).toByte()
        val extra = Crypto.randomBytes(2)
        tailPlain[6] = extra[0]
        tailPlain[7] = extra[1]

        val encryptedFull = Crypto.CtrStream(key, iv).update(rnd)
        val result = rnd.copyOf()
        for (i in 0 until 8) {
            val keystream = encryptedFull[56 + i].toInt() xor rnd[56 + i].toInt()
            result[Const.PROTO_TAG_POS + i] = (tailPlain[i].toInt() xor keystream).toByte()
        }
        return result
    }
}
