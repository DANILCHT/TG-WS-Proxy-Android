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
    private val variants = RelayEndpoint.parseWorkers(listOf("w.example.workers.dev"), allowTls = true)
    private val plain = variants.first { !it.secure }
    private val tls = variants.first { it.secure }

    private fun <T> withPool(block: (RelayPool) -> T): T {
        val executor = Executors.newSingleThreadExecutor()
        try {
            return block(RelayPool(executor))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun disablesWorkerAfterHttp429() = withPool { pool ->
        pool.reportFailure(ep, WsHandshakeError(429, "Too Many Requests"))
        assertFalse(pool.availableEndpoints(listOf(ep)).contains(ep))
    }

    @Test
    fun quotaCoversBothVariantsOfAWorker() = withPool { pool ->
        pool.reportFailure(tls, WsHandshakeError(429, "Too Many Requests"))
        assertEquals(listOf(other), pool.availableEndpoints(variants + other))
    }

    @Test
    fun otherErrorsOnlyDemote() = withPool { pool ->
        pool.reportFailure(ep, WsHandshakeError(503, "Service Unavailable"))
        val list = pool.availableEndpoints(listOf(ep, other))
        assertEquals(listOf(other, ep), list)

        pool.reportSuccess(ep)
        assertTrue(pool.availableEndpoints(listOf(ep)).contains(ep))
    }

    @Test
    fun plainVariantLeadsUntilTlsWins() = withPool { pool ->
        assertEquals(listOf(plain, tls), pool.availableEndpoints(variants))
        pool.reportSuccess(tls)
        assertEquals(listOf(tls, plain), pool.availableEndpoints(variants))
    }

    @Test
    fun failedVariantFallsBehindItsTwin() = withPool { pool ->
        pool.reportFailure(plain, java.net.SocketTimeoutException("timed out"))
        assertEquals(listOf(tls, plain), pool.availableEndpoints(variants))
    }

    @Test
    fun frozenTlsVariantGoesLast() = withPool { pool ->
        pool.reportSuccess(tls)
        pool.reportFrozen(tls)
        assertEquals(listOf(plain, tls), pool.availableEndpoints(variants))
    }

    @Test
    fun recentWinnerHostGoesFirst() = withPool { pool ->
        pool.reportSuccess(other)
        assertEquals(other, pool.availableEndpoints(variants + other).first())
    }
}
