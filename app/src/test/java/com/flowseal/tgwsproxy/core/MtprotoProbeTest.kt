package com.flowseal.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MtprotoProbeTest {

    private fun intLe(b: ByteArray, off: Int): Int =
        (0 until 4).fold(0) { acc, i -> acc or ((b[off + i].toInt() and 0xFF) shl (8 * i)) }

    @Test
    fun reqPqIsAnAbridgedUnencryptedMessage() {
        val pkt = MtprotoProbe.reqPqPacket(nowMs = 1_790_000_000_123L)
        assertEquals(41, pkt.size)
        assertEquals(10, pkt[0].toInt()) // 40 bytes / 4
        for (i in 1..8) assertEquals("auth_key_id must be zero", 0, pkt[i].toInt())
        val msgIdLow = intLe(pkt, 9)
        assertEquals("msg_id divisible by 4", 0, msgIdLow and 3)
        assertEquals(1_790_000_000, intLe(pkt, 13))
        assertEquals(20, intLe(pkt, 17))
        assertEquals(0xBE7E8EF1.toInt(), intLe(pkt, 21))
    }

    @Test
    fun resPqIsRecognised() {
        val msg = ByteArray(1 + 20 + 4 + 60)
        msg[0] = ((msg.size - 1) / 4).toByte()
        val cons = 0x05162463
        for (i in 0 until 4) msg[21 + i] = ((cons shr (8 * i)) and 0xFF).toByte()
        assertTrue(MtprotoProbe.isResPq(msg))

        msg[21] = 0
        assertFalse(MtprotoProbe.isResPq(msg))
        assertFalse(MtprotoProbe.isResPq(ByteArray(0)))
        assertFalse(MtprotoProbe.isResPq(ByteArray(10)))
    }

    @Test
    fun longAbridgedHeaderIsHandled() {
        val msg = ByteArray(4 + 20 + 4)
        msg[0] = 0x7F
        val cons = 0x05162463
        for (i in 0 until 4) msg[24 + i] = ((cons shr (8 * i)) and 0xFF).toByte()
        assertTrue(MtprotoProbe.isResPq(msg))
    }
}
