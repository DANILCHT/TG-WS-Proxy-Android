package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.RawWebSocket

/**
 * End-to-end check of an upstream route: sends an obfuscated init and an
 * unencrypted `req_pq_multi` through the WebSocket and waits for Telegram's
 * `resPQ`. A 101 from Cloudflare or a relay only proves that hop is reachable;
 * a resPQ proves Telegram answers through it.
 *
 * Nothing account-related is sent: req_pq_multi is the first message of the
 * MTProto key exchange and carries only a random nonce.
 */
object MtprotoProbe {

    private const val REQ_PQ_MULTI = 0xBE7E8EF1.toInt()
    private const val RES_PQ = 0x05162463

    /** Returns null when Telegram answered, otherwise a short reason. */
    fun check(ws: RawWebSocket, dc: Int, timeoutMs: Int = 6_000): String? {
        val init = Obfuscated.generateRelayInit(Const.PROTO_TAG_ABRIDGED, dc)
        val enc = Crypto.CtrStream(init.copyOfRange(8, 40), init.copyOfRange(40, 56))
        enc.skip(64)
        val rev = Crypto.reversed(init.copyOfRange(8, 56))
        val dec = Crypto.CtrStream(rev.copyOfRange(0, 32), rev.copyOfRange(32, 48))

        ws.setReadTimeout(timeoutMs)
        ws.send(init)
        ws.send(enc.update(reqPqPacket()))
        val data = ws.recv() ?: return "connection closed without an answer"
        return if (isResPq(dec.update(data))) null else "unexpected answer (${data.size} bytes)"
    }

    /** Abridged-framed unencrypted message holding req_pq_multi. */
    internal fun reqPqPacket(nowMs: Long = System.currentTimeMillis()): ByteArray {
        val body = ByteArray(20)
        putIntLe(body, 0, REQ_PQ_MULTI)
        System.arraycopy(Crypto.randomBytes(16), 0, body, 4, 16)

        val msgId = (((nowMs / 1000) shl 32) or (((nowMs % 1000) shl 32) / 1000)) and 3L.inv()
        val msg = ByteArray(8 + 8 + 4 + body.size) // auth_key_id = 0
        for (i in 0 until 8) msg[8 + i] = ((msgId shr (8 * i)) and 0xFF).toByte()
        putIntLe(msg, 16, body.size)
        System.arraycopy(body, 0, msg, 20, body.size)

        return byteArrayOf((msg.size / 4).toByte()) + msg
    }

    /** True when [plain] (abridged framing) carries a resPQ. */
    internal fun isResPq(plain: ByteArray): Boolean {
        if (plain.isEmpty()) return false
        val header = if ((plain[0].toInt() and 0xFF) == 0x7F) 4 else 1
        val consOff = header + 20 // auth_key_id + msg_id + length
        if (plain.size < consOff + 4) return false
        return getIntLe(plain, consOff) == RES_PQ
    }

    private fun putIntLe(b: ByteArray, off: Int, v: Int) {
        for (i in 0 until 4) b[off + i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

    private fun getIntLe(b: ByteArray, off: Int): Int {
        var v = 0
        for (i in 0 until 4) v = v or ((b[off + i].toInt() and 0xFF) shl (8 * i))
        return v
    }
}
