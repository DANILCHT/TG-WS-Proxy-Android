package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.WsHandshakeError
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Executors

class CfWorkerPoolTest {

    @Test
    fun disablesWorkerAfterHttp429() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val pool = CfWorkerPool(executor)
            val domain = "worker.example.com"

            pool.reportFailure(domain, WsHandshakeError(429, "Too Many Requests"))

            assertFalse(pool.availableDomains(listOf(domain)).contains(domain))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun keepsWorkerAvailableAfterOtherHandshakeErrors() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            val pool = CfWorkerPool(executor)
            val domain = "worker.example.com"

            pool.reportFailure(domain, WsHandshakeError(503, "Service Unavailable"))

            assertTrue(pool.availableDomains(listOf(domain)).contains(domain))
        } finally {
            executor.shutdownNow()
        }
    }
}
