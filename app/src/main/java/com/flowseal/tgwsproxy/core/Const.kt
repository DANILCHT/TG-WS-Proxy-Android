package com.flowseal.tgwsproxy.core

import java.util.Locale

/**
 * Port of proxy/utils.py — protocol constants, DC tables and small helpers.
 */
object Const {

    val ZERO_64 = ByteArray(64)

    const val HANDSHAKE_LEN = 64
    const val SKIP_LEN = 8
    const val PREKEY_LEN = 32
    const val KEY_LEN = 32
    const val IV_LEN = 16
    const val PROTO_TAG_POS = 56
    const val DC_IDX_POS = 60

    val PROTO_TAG_ABRIDGED = byteArrayOf(0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte())
    val PROTO_TAG_INTERMEDIATE = byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())
    val PROTO_TAG_SECURE = byteArrayOf(0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte())

    const val PROTO_ABRIDGED_INT = 0xEFEFEFEF.toInt()
    const val PROTO_INTERMEDIATE_INT = 0xEEEEEEEE.toInt()
    const val PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD.toInt()

    val RESERVED_FIRST_BYTES = setOf(0xEF)

    /** Forbidden first 4 bytes of a generated relay init (HEAD/POST/GET /ee/dd/TLS/OPTIONS). */
    val RESERVED_STARTS: List<ByteArray> = listOf(
        byteArrayOf(0x48, 0x45, 0x41, 0x44),
        byteArrayOf(0x50, 0x4F, 0x53, 0x54),
        byteArrayOf(0x47, 0x45, 0x54, 0x20),
        byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte()),
        byteArrayOf(0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte()),
        byteArrayOf(0x16, 0x03, 0x01, 0x02),
        byteArrayOf(0x4F, 0x50, 0x54, 0x49),
    )
    val RESERVED_CONTINUE = byteArrayOf(0, 0, 0, 0)

    val DC_DEFAULT_IPS: Map<Int, String> = mapOf(
        1 to "149.154.175.50",
        2 to "149.154.167.51",
        3 to "149.154.175.100",
        4 to "149.154.167.91",
        5 to "149.154.171.5",
        203 to "91.105.192.100",
    )

    val DC_TEST_IPS: Map<Int, String> = mapOf(
        1 to "149.154.175.10",
        2 to "149.154.167.40",
        3 to "149.154.175.117",
    )

    const val WS_PATH = "/apiws"
    const val WS_PATH_TEST = WS_PATH + "_test"

    /** Upstream 1.12.0: non-media goes to kwsN only, media tries kwsN-1 first. */
    fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
        val d = if (dc == 203) 2 else dc
        return if (isMedia) {
            listOf("kws$d-1.web.telegram.org", "kws$d.web.telegram.org")
        } else {
            listOf("kws$d.web.telegram.org")
        }
    }

    fun humanBytes(bytes: Long): String {
        var n = bytes.toDouble()
        for (unit in arrayOf("B", "KB", "MB", "GB")) {
            if (Math.abs(n) < 1024) return String.format(Locale.US, "%.1f%s", n, unit)
            n /= 1024
        }
        return String.format(Locale.US, "%.1fTB", n)
    }

    fun startsWith(data: ByteArray, prefix: ByteArray): Boolean {
        if (data.size < prefix.size) return false
        for (i in prefix.indices) if (data[i] != prefix[i]) return false
        return true
    }

    fun regionEquals(data: ByteArray, off: Int, other: ByteArray): Boolean {
        if (off + other.size > data.size) return false
        for (i in other.indices) if (data[off + i] != other[i]) return false
        return true
    }

    fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(String.format("%02x", b))
        return sb.toString()
    }

    fun fromHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex string must have even length" }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = ((hexDigit(hex[i * 2]) shl 4) or hexDigit(hex[i * 2 + 1])).toByte()
        }
        return out
    }

    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("invalid hex char: $c")
    }
}
