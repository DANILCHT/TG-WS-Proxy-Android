package com.flowseal.tgwsproxy.net

/**
 * Locates a split point inside a TLS ClientHello so it can be written to the
 * socket in more than one TCP segment.
 *
 * Middleboxes that filter by SNI usually parse the first packet of a connection
 * on its own. Cutting the hostname in half means neither segment contains a
 * complete SNI extension, which is enough for naive filters. A box that
 * reassembles the TCP stream before parsing is unaffected — this is a cheap
 * trick, not a guarantee.
 */
object TlsFragmenter {

    private const val RECORD_HEADER = 5
    private const val TYPE_HANDSHAKE = 0x16
    private const val HANDSHAKE_CLIENT_HELLO = 0x01
    private const val EXT_SERVER_NAME = 0x0000

    /** Fallback split offset when the SNI extension cannot be located. */
    const val FALLBACK_SPLIT = 40

    /**
     * Returns the offset inside [data] (0 until [len]) where the buffer should
     * be cut, or -1 when it should be written in one piece.
     */
    fun splitPoint(data: ByteArray, len: Int): Int {
        if (len < RECORD_HEADER + 4) return -1
        if ((data[0].toInt() and 0xFF) != TYPE_HANDSHAKE) return -1
        if ((data[RECORD_HEADER].toInt() and 0xFF) != HANDSHAKE_CLIENT_HELLO) return -1

        val hostRange = findSniHost(data, len)
        if (hostRange != null) {
            val (off, hostLen) = hostRange
            // Cut in the middle of the hostname; guarantee both parts non-empty.
            val mid = off + hostLen / 2
            if (mid in 1 until len) return mid
        }

        return if (len > FALLBACK_SPLIT) FALLBACK_SPLIT else -1
    }

    /** Returns offset and length of the SNI hostname bytes, or null. */
    private fun findSniHost(data: ByteArray, len: Int): Pair<Int, Int>? {
        var p = RECORD_HEADER + 1 // handshake type
        p += 3 // handshake length
        p += 2 // client_version
        p += 32 // random
        if (p >= len) return null

        val sessionIdLen = u8(data, p, len) ?: return null
        p += 1 + sessionIdLen

        val cipherLen = u16(data, p, len) ?: return null
        p += 2 + cipherLen

        val compressionLen = u8(data, p, len) ?: return null
        p += 1 + compressionLen

        val extensionsLen = u16(data, p, len) ?: return null
        p += 2
        val extensionsEnd = minOf(p + extensionsLen, len)

        while (p + 4 <= extensionsEnd) {
            val type = u16(data, p, len) ?: return null
            val size = u16(data, p + 2, len) ?: return null
            val body = p + 4
            if (body + size > extensionsEnd) return null

            if (type == EXT_SERVER_NAME) {
                // server_name_list<2> { name_type<1> host_name<2> }
                var q = body + 2
                while (q + 3 <= body + size) {
                    val nameType = u8(data, q, len) ?: return null
                    val hostLen = u16(data, q + 1, len) ?: return null
                    val hostOff = q + 3
                    if (hostOff + hostLen > body + size) return null
                    if (nameType == 0 && hostLen >= 2) return hostOff to hostLen
                    q = hostOff + hostLen
                }
                return null
            }
            p = body + size
        }
        return null
    }

    private fun u8(data: ByteArray, off: Int, len: Int): Int? =
        if (off < 0 || off >= len) null else data[off].toInt() and 0xFF

    private fun u16(data: ByteArray, off: Int, len: Int): Int? {
        if (off < 0 || off + 1 >= len) return null
        return ((data[off].toInt() and 0xFF) shl 8) or (data[off + 1].toInt() and 0xFF)
    }
}
