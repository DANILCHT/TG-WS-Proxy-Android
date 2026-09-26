package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.Tls
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayEndpointTest {

    @Test
    fun bareDomainIsWorkerStyle() {
        val e = RelayEndpoint.parse("abc.user.workers.dev")!!
        assertTrue(e.secure)
        assertEquals(443, e.port)
        assertEquals("/apiws", e.path)
        assertEquals("abc.user.workers.dev", e.connectAddr)
        assertEquals("/apiws?dst=149.154.167.51&dc=2", e.requestPath("149.154.167.51", 2))
        assertEquals(Tls.Verify.FULL, e.verifyMode())
    }

    @Test
    fun noSecureDefaultsToPort80() {
        val e = RelayEndpoint.parse("abc.workers.dev", defaultSecure = false)!!
        assertFalse(e.secure)
        assertEquals(80, e.port)
    }

    @Test
    fun explicitSchemeWinsOverDefault() {
        assertTrue(RelayEndpoint.parse("wss://a.example.com", defaultSecure = false)!!.secure)
        assertFalse(RelayEndpoint.parse("ws://a.example.com", defaultSecure = true)!!.secure)
    }

    @Test
    fun plainIpWithPortAndPath() {
        val e = RelayEndpoint.parse("ws://203.0.113.7:8080/tg")!!
        assertEquals("203.0.113.7", e.host)
        assertEquals(8080, e.port)
        assertEquals("/tg?dst=1.2.3.4&dc=4", e.requestPath("1.2.3.4", 4))
    }

    @Test
    fun overridesAreParsed() {
        val e = RelayEndpoint.parse(
            "wss://relay.example.ru/apiws?ip=203.0.113.7&sni=vk.com&key=s3cr%2Bt&verify=0"
        )!!
        assertEquals("203.0.113.7", e.connectAddr)
        assertEquals("vk.com", e.sni)
        assertEquals("s3cr+t", e.key)
        assertEquals(Tls.Verify.NONE, e.verifyMode())
        assertEquals("/apiws?dst=1.2.3.4&dc=1&key=s3cr%2Bt", e.requestPath("1.2.3.4", 1))
    }

    @Test
    fun sniOverrideChecksChainOnly() {
        val e = RelayEndpoint.parse("wss://relay.example.ru?sni=vk.com")!!
        assertEquals(Tls.Verify.CHAIN, e.verifyMode())
    }

    @Test
    fun unknownParamsStayInPath() {
        val e = RelayEndpoint.parse("wss://relay.example.ru/x?foo=bar")!!
        assertEquals("/x?foo=bar&dst=1.2.3.4&dc=5", e.requestPath("1.2.3.4", 5))
    }

    @Test
    fun rejectsGarbage() {
        assertNull(RelayEndpoint.parse("ftp://a.example.com"))
        assertNull(RelayEndpoint.parse("not a host"))
        assertNull(RelayEndpoint.parse("a.example.com:99999"))
        assertNull(RelayEndpoint.parse("a.example.com?ip=nope"))
        assertNull(RelayEndpoint.parse("user@a.example.com"))
        assertNull(RelayEndpoint.parse("# comment"))
    }

    @Test
    fun listDedupesAndReportsInvalid() {
        val list = RelayEndpoint.parseList(listOf("a.example.com\nwss://a.example.com/apiws", "b.example.com"))
        assertEquals(2, list.size)
        assertEquals(listOf("bad_host"), RelayEndpoint.invalidEntries(listOf("a.example.com bad_host")))
    }
}
