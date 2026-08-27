package com.flowseal.tgwsproxy.core

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Port of proxy/_aes.py.
 *
 * JCE's "AES/CTR/NoPadding" is a stream cipher: successive update() calls keep
 * the counter/keystream position, which is exactly the behaviour the Python
 * code relies on. CTR is symmetric, so a single ENCRYPT_MODE instance is used
 * for both directions just like the Python shim does.
 */
object Crypto {

    private val rng = SecureRandom()

    fun randomBytes(n: Int): ByteArray {
        val b = ByteArray(n)
        rng.nextBytes(b)
        return b
    }

    fun randomHex(n: Int): String = Const.toHex(randomBytes(n))

    fun randomInt(bound: Int): Int = rng.nextInt(bound)

    private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /**
     * Standard base64 with padding. Implemented here instead of using
     * android.util.Base64 so the networking layer stays testable on the JVM.
     */
    fun base64(data: ByteArray): String {
        val sb = StringBuilder(((data.size + 2) / 3) * 4)
        var i = 0
        while (i + 2 < data.size) {
            val v = ((data[i].toInt() and 0xFF) shl 16) or
                ((data[i + 1].toInt() and 0xFF) shl 8) or
                (data[i + 2].toInt() and 0xFF)
            sb.append(B64[(v shr 18) and 0x3F])
            sb.append(B64[(v shr 12) and 0x3F])
            sb.append(B64[(v shr 6) and 0x3F])
            sb.append(B64[v and 0x3F])
            i += 3
        }
        when (data.size - i) {
            1 -> {
                val v = (data[i].toInt() and 0xFF) shl 16
                sb.append(B64[(v shr 18) and 0x3F])
                sb.append(B64[(v shr 12) and 0x3F])
                sb.append("==")
            }

            2 -> {
                val v = ((data[i].toInt() and 0xFF) shl 16) or
                    ((data[i + 1].toInt() and 0xFF) shl 8)
                sb.append(B64[(v shr 18) and 0x3F])
                sb.append(B64[(v shr 12) and 0x3F])
                sb.append(B64[(v shr 6) and 0x3F])
                sb.append('=')
            }
        }
        return sb.toString()
    }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** Constant-time comparison of the first [len] bytes. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray, len: Int): Boolean {
        if (a.size < len || b.size < len) return false
        var diff = 0
        for (i in 0 until len) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun reversed(b: ByteArray): ByteArray {
        val out = ByteArray(b.size)
        for (i in b.indices) out[i] = b[b.size - 1 - i]
        return out
    }

    /** Stateful AES-CTR keystream, equivalent to `Cipher(...).encryptor()`. */
    class CtrStream(key: ByteArray, iv: ByteArray) {
        private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding")

        init {
            require(key.size == 16 || key.size == 24 || key.size == 32) {
                "AES key must be 16/24/32 bytes, got ${key.size}"
            }
            require(iv.size == 16) { "CTR IV must be 16 bytes, got ${iv.size}" }
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        }

        fun update(data: ByteArray): ByteArray = update(data, 0, data.size)

        fun update(data: ByteArray, off: Int, len: Int): ByteArray {
            if (len == 0) return ByteArray(0)
            return cipher.update(data, off, len) ?: ByteArray(0)
        }

        /** In-place variant used on the hot path to avoid an extra allocation. */
        fun updateInto(data: ByteArray, off: Int, len: Int, out: ByteArray, outOff: Int): Int {
            if (len == 0) return 0
            return cipher.update(data, off, len, out, outOff)
        }

        /** Advances the keystream without keeping the output (fast-forward). */
        fun skip(nBytes: Int) {
            update(ByteArray(nBytes))
        }
    }
}
