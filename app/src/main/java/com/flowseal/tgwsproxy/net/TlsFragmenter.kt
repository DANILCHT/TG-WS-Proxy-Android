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

    /**
     * Re-frames the first TLS record of [data] as two records split at [cut]
     * (an offset inside that record's payload, counted from the start of
     * [data]). Returns the two pieces to send as separate TCP segments: the
     * first record, then the second one followed by whatever came after the
     * original record. Null when [data] does not start with one complete
     * handshake record or [cut] is not inside its payload.
     *
     * A ClientHello spread over two records hides the SNI from filters that
     * reassemble the TCP stream but parse only the first TLS record (the
     * `tlsrec` trick of zapret/ByeDPI). Servers must accept fragmented
     * handshake messages, and Cloudflare and Telegram do.
     */
    fun splitIntoRecords(data: ByteArray, len: Int, cut: Int): Pair<ByteArray, ByteArray>? {
        if (len < RECORD_HEADER + 2) return null
        if ((data[0].toInt() and 0xFF) != TYPE_HANDSHAKE) return null
        val recLen = u16(data, 3, len) ?: return null
        val recEnd = RECORD_HEADER + recLen
        if (recEnd > len) return null
        if (cut <= RECORD_HEADER || cut >= recEnd) return null

        val firstBody = cut - RECORD_HEADER
        val secondBody = recLen - firstBody
        val trailing = len - recEnd

        val first = ByteArray(RECORD_HEADER + firstBody)
        System.arraycopy(data, 0, first, 0, 3) // content type + legacy version
        first[3] = ((firstBody shr 8) and 0xFF).toByte()
        first[4] = (firstBody and 0xFF).toByte()
        System.arraycopy(data, RECORD_HEADER, first, RECORD_HEADER, firstBody)

        val second = ByteArray(RECORD_HEADER + secondBody + trailing)
        System.arraycopy(data, 0, second, 0, 3)
        second[3] = ((secondBody shr 8) and 0xFF).toByte()
        second[4] = (secondBody and 0xFF).toByte()
        System.arraycopy(data, cut, second, RECORD_HEADER, secondBody + trailing)
        return first to second
    }

    /**
     * Split point in the middle of the Host header value of an HTTP request, or
     * -1. Used for plain ws:// connections (port 80), where the domain travels
     * in the Host header instead of the SNI.
     */
    fun httpSplitPoint(data: ByteArray, len: Int): Int {
        if (len < 16) return -1
        val head = String(data, 0, minOf(len, 4096), Charsets.ISO_8859_1)
        if (!head.startsWith("GET ")) return -1
        val marker = head.indexOf("\r\nHost:", ignoreCase = true)
        if (marker < 0) return -1
        var start = marker + "\r\nHost:".length
        while (start < head.length && head[start] == ' ') start++
        val end = head.indexOf("\r\n", start)
        if (end < 0 || end - start < 2) return -1
        return start + (end - start) / 2
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
