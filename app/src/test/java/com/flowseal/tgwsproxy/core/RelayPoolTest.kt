package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.WsHandshakeError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Executors

class RelayPoolTest {

    private val ep = RelayEndpoint.parse("worker.example.com")!!
    private val other = RelayEndpoint.parse("relay.example.ru")!!

    @Test
    fun disablesWorkerAfterHttp429() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val pool = RelayPool(executor)
            pool.reportFailure(ep, WsHandshakeError(429, "Too Many Requests"))
            assertFalse(pool.availableEndpoints(listOf(ep)).contains(ep))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun otherErrorsOnlyDemote() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val pool = RelayPool(executor)
            pool.reportFailure(ep, WsHandshakeError(503, "Service Unavailable"))
            val list = pool.availableEndpoints(listOf(ep, other))
            assertEquals(listOf(other, ep), list)

            pool.reportSuccess(ep)
            assertTrue(pool.availableEndpoints(listOf(ep)).contains(ep))
        } finally {
            executor.shutdownNow()
        }
    }
}
