package com.flowseal.tgwsproxy.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsTest {

    @Test
    fun queryHasHeaderQuestionAndTypeA() {
        val q = Dns.buildQuery("kws2.example.com", 0x1234)
        assertEquals(0x12, q[0].toInt() and 0xFF)
        assertEquals(0x34, q[1].toInt() and 0xFF)
        assertEquals(1, q[5].toInt()) // QDCOUNT
        assertEquals(4, q[12].toInt()) // "kws2"
        assertEquals(1, q[q.size - 3].toInt()) // QTYPE A
        assertEquals(1, q[q.size - 1].toInt()) // QCLASS IN
    }

    @Test
    fun parsesCompressedAnswers() {
        val query = Dns.buildQuery("a.example.com", 7)
        val header = byteArrayOf(0, 7, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 2, 0, 0, 0, 0)
        val body = query.copyOfRange(12, query.size)
        fun rr(type: Int, data: ByteArray) =
            byteArrayOf(0xC0.toByte(), 12, 0, type.toByte(), 0, 1, 0, 0, 0, 60, 0, data.size.toByte()) + data
        val msg = header + body +
            rr(5, byteArrayOf(1, 'x'.code.toByte(), 0)) + // CNAME, skipped
            rr(1, byteArrayOf(93, 184.toByte(), 216.toByte(), 34))
        val ips = Dns.parseAnswer(msg)
        assertEquals(1, ips.size)
        assertArrayEquals(byteArrayOf(93, 184.toByte(), 216.toByte(), 34), ips[0])
    }

    @Test
    fun errorResponseYieldsNothing() {
        val header = byteArrayOf(0, 7, 0x81.toByte(), 0x83.toByte(), 0, 0, 0, 0, 0, 0, 0, 0)
        assertTrue(Dns.parseAnswer(header).isEmpty())
    }

    @Test
    fun base64UrlHasNoPaddingOrUnsafeChars() {
        val s = Dns.base64Url(byteArrayOf(-1, -2, -3, -4))
        assertTrue(!s.contains('=') && !s.contains('+') && !s.contains('/'))
    }

    private fun ip(s: String) = java.net.InetAddress.getByAddress(
        s.split('.').map { it.toInt().toByte() }.toByteArray()
    )

    @Test
    fun recognisesCloudflareRanges() {
        for (a in listOf("104.21.32.1", "172.67.200.5", "188.114.97.3", "162.159.1.1", "104.16.0.0")) {
            assertTrue(a, Dns.isCloudflare(ip(a)))
        }
        for (a in listOf("149.154.167.220", "95.167.1.1", "10.0.0.1", "104.32.0.1", "172.72.0.1")) {
            assertFalse(a, Dns.isCloudflare(ip(a)))
        }
    }
}
