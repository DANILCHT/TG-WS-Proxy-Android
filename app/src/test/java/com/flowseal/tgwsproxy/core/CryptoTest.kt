package com.flowseal.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the AES-CTR shim that replaces Python's `cryptography` package.
 * The whole bridge depends on `update()` keeping the keystream position across
 * calls, so that is verified explicitly with the NIST vector.
 */
class CryptoTest {

    // NIST SP 800-38A, F.5.1 CTR-AES128.Encrypt
    private val key = Const.fromHex("2b7e151628aed2a6abf7158809cf4f3c")
    private val iv = Const.fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

    private val plaintextBlocks = listOf(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    )

    private val ciphertextBlocks = listOf(
        "874d6191b620e3261bef6864990db6ce",
        "9806f66b7970fdff8617187bb9fffdff",
        "5ae4df3edbd5d35e5b4f09020db03eab",
        "1e031dda2fbe03d1792170a0f3009cee",
    )

    @Test
    fun matchesNistCtrVectorInOneShot() {
        val stream = Crypto.CtrStream(key, iv)
        val plain = Const.fromHex(plaintextBlocks.joinToString(""))
        val out = stream.update(plain)
        assertEquals(ciphertextBlocks.joinToString(""), Const.toHex(out))
    }

    @Test
    fun keystreamContinuesAcrossUpdateCalls() {
        val stream = Crypto.CtrStream(key, iv)
        val out = StringBuilder()
        for (block in plaintextBlocks) {
            out.append(Const.toHex(stream.update(Const.fromHex(block))))
        }
        assertEquals(ciphertextBlocks.joinToString(""), out.toString())
    }

    @Test
    fun keystreamContinuesAcrossUnalignedUpdateCalls() {
        val stream = Crypto.CtrStream(key, iv)
        val plain = Const.fromHex(plaintextBlocks.joinToString(""))
        val out = java.io.ByteArrayOutputStream()
        var offset = 0
        for (size in listOf(1, 5, 7, 3, 16, 20)) {
            val take = minOf(size, plain.size - offset)
            if (take <= 0) break
            out.write(stream.update(plain, offset, take))
            offset += take
        }
        if (offset < plain.size) out.write(stream.update(plain, offset, plain.size - offset))
        assertEquals(ciphertextBlocks.joinToString(""), Const.toHex(out.toByteArray()))
    }

    @Test
    fun skipAdvancesKeystreamLikePythonFastForward() {
        val skipped = Crypto.CtrStream(key, iv)
        skipped.skip(32)
        val afterSkip = skipped.update(Const.fromHex(plaintextBlocks[2]))

        val direct = Crypto.CtrStream(key, iv)
        direct.update(Const.fromHex(plaintextBlocks[0] + plaintextBlocks[1]))
        val expected = direct.update(Const.fromHex(plaintextBlocks[2]))

        assertTrue(afterSkip.contentEquals(expected))
    }

    @Test
    fun ctrIsSymmetric() {
        val data = Crypto.randomBytes(1000)
        val encrypted = Crypto.CtrStream(key, iv).update(data)
        val decrypted = Crypto.CtrStream(key, iv).update(encrypted)
        assertTrue(decrypted.contentEquals(data))
    }

    @Test
    fun reversedMatchesPythonSliceReverse() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        assertTrue(Crypto.reversed(data).contentEquals(byteArrayOf(5, 4, 3, 2, 1)))
    }

    @Test
    fun constantTimeEqualsComparesOnlyThePrefix() {
        val a = Const.fromHex("00112233445566778899aabbccddeeff")
        val b = Const.fromHex("00112233445566778899aabbccdd0000")
        assertTrue(Crypto.constantTimeEquals(a, b, 14))
        assertFalse(Crypto.constantTimeEquals(a, b, 16))
        assertFalse(Crypto.constantTimeEquals(a, ByteArray(4), 8))
    }
}
