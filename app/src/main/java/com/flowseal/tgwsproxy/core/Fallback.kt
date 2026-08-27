package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.DataStream
import com.flowseal.tgwsproxy.net.RawWebSocket
import com.flowseal.tgwsproxy.net.SocketStream
import com.flowseal.tgwsproxy.net.Tls

/**
 * Port of the fallback ladder in proxy/bridge.py: CF Worker -> CF proxy -> plain
 * TCP to the DC. Used when the direct WebSocket route is unavailable.
 */
class Fallback(
    private val config: ProxyConfig,
    private val cfWorkerPool: CfWorkerPool,
) {

    fun doFallback(
        client: DataStream,
        relayInit: ByteArray,
        label: String,
        dc: Int,
        isTestDc: Boolean,
        isMedia: Boolean,
        mediaTag: String,
        ctx: CryptoCtx,
        splitter: MsgSplitter?,
    ): Boolean {
        val ipTable = if (isTestDc) Const.DC_TEST_IPS else Const.DC_DEFAULT_IPS
        val fallbackDst = ipTable[dc]
        val useCf = config.fallbackCfproxy && !isTestDc
        val workerDomains = config.cfproxyWorkerDomains

        val methods = ArrayList<String>(3)
        if (workerDomains.isNotEmpty() && fallbackDst != null) methods.add("cf_worker")
        if (useCf) methods.add("cf")
        if (fallbackDst != null) methods.add("tcp")

        for (method in methods) {
            when {
                method == "cf_worker" && fallbackDst != null -> {
                    if (cfWorkerFallback(
                            client, relayInit, label, ctx,
                            dc, isTestDc, isMedia, fallbackDst,
                        )
                    ) return true
                }

                method == "cf" -> {
                    if (cfProxyFallback(client, relayInit, label, ctx, dc, isMedia, splitter)) {
                        return true
                    }
                }

                method == "tcp" && fallbackDst != null -> {
                    Logger.i("[$label] DC$dc$mediaTag -> TCP fallback to $fallbackDst:443")
                    if (tcpFallback(client, fallbackDst, 443, relayInit, label, ctx)) return true
                }
            }
        }
        return false
    }

    private fun cfWorkerFallback(
        client: DataStream,
        relayInit: ByteArray,
        label: String,
        ctx: CryptoCtx,
        dc: Int,
        isTestDc: Boolean,
        isMedia: Boolean,
        fallbackDst: String,
    ): Boolean {
        val mediaTag = if (isMedia) " media" else ""
        val workerDomains = config.cfproxyWorkerDomains
        if (workerDomains.isEmpty()) return false

        var ws: RawWebSocket? = null

        val pooled = if (isTestDc) null else cfWorkerPool.get(dc, fallbackDst, workerDomains)
        if (pooled != null) {
            ws = pooled.ws
            Logger.i(
                "[$label] DC$dc$mediaTag -> CF worker pool hit via " +
                    "${pooled.workerDomain} for $fallbackDst"
            )
        } else {
            val path = "/apiws?dst=${java.net.URLEncoder.encode(fallbackDst, "UTF-8")}&dc=$dc"
            for (workerDomain in cfWorkerPool.availableDomains(workerDomains)) {
                Logger.i("[$label] DC$dc$mediaTag -> trying CF worker $workerDomain for $fallbackDst")
                try {
                    ws = RawWebSocket.connect(
                        host = workerDomain, domain = workerDomain, timeoutMs = 10_000,
                        path = path, bufferSize = config.bufferSize,
                    )
                    break
                } catch (e: Exception) {
                    cfWorkerPool.reportFailure(workerDomain, e)
                    Logger.w("[$label] DC$dc$mediaTag CF worker $workerDomain failed: $e")
                }
            }
            if (ws == null) return false
        }

        Stats.connectionsCfproxy.incrementAndGet()
        ws.setReadTimeout(0)
        ws.send(relayInit)
        Bridge.bridgeWsReencrypt(client, ws, label, ctx, dc, isMedia, splitter = null)
        return true
    }

    private fun cfProxyFallback(
        client: DataStream,
        relayInit: ByteArray,
        label: String,
        ctx: CryptoCtx,
        dc: Int,
        isMedia: Boolean,
        splitter: MsgSplitter?,
    ): Boolean {
        val mediaTag = if (isMedia) " media" else ""
        var ws: RawWebSocket? = null
        var chosenDomain: String? = null

        Logger.i("[$label] DC$dc$mediaTag -> trying CF proxy")

        for (baseDomain in Balancer.getDomainsForDc(dc)) {
            val domain = "kws$dc.$baseDomain"
            try {
                ws = RawWebSocket.connect(
                    host = domain, domain = domain, timeoutMs = 10_000,
                    bufferSize = config.bufferSize,
                )
                chosenDomain = baseDomain
                break
            } catch (e: Exception) {
                Logger.w("[$label] DC$dc$mediaTag CF proxy failed: $e")
            }
        }

        if (ws == null) return false

        if (chosenDomain != null && Balancer.updateDomainForDc(dc, chosenDomain)) {
            Logger.i("[$label] Switched active CF domain")
        }

        Stats.connectionsCfproxy.incrementAndGet()
        ws.setReadTimeout(0)
        ws.send(relayInit)
        Bridge.bridgeWsReencrypt(client, ws, label, ctx, dc, isMedia, splitter)
        return true
    }

    private fun tcpFallback(
        client: DataStream,
        dst: String,
        port: Int,
        relayInit: ByteArray,
        label: String,
        ctx: CryptoCtx,
    ): Boolean {
        val socket = try {
            Tls.connectPlain(dst, port, 10_000, config.bufferSize)
        } catch (e: Exception) {
            Logger.w("[$label] TCP fallback to $dst:$port failed: $e")
            return false
        }

        Stats.connectionsTcpFallback.incrementAndGet()
        val remote = SocketStream(socket, 32 * 1024)
        remote.write(relayInit)
        remote.flush()
        Bridge.bridgeTcpReencrypt(client, remote, label, ctx)
        return true
    }
}
