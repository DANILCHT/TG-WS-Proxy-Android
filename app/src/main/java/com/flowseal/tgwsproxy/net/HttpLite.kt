package com.flowseal.tgwsproxy.net

import com.flowseal.tgwsproxy.core.Logger
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.net.Socket
import java.net.URI

/**
 * Minimal HTTP/1.1 client over the same socket plumbing as the proxy itself.
 *
 * Exists because HttpURLConnection can neither connect to a chosen IP while
 * presenting a different host name, nor resolve through [Dns]. Both matter on
 * networks that poison DNS for GitHub: update checks, APK downloads, the CF
 * domain list and DoH all go through here.
 *
 * TLS is always fully verified against the URL's host name.
 */
object HttpLite {

    class Request(
        val url: String,
        /** Connect to this IP instead of resolving the URL's host. */
        val connectAddr: String? = null,
        val timeoutMs: Int = 15_000,
        val headers: Map<String, String> = emptyMap(),
        val maxBytes: Int = 1 shl 20,
        /** When false and no [connectAddr] is given, only [PINNED] is used. */
        val useDns: Boolean = true,
        val maxRedirects: Int = 5,
    )

    class Response(
        val status: Int,
        val headers: Map<String, String>,
        val body: ByteArray,
        val finalUrl: String,
    ) {
        fun text(): String = String(body, Charsets.UTF_8)
    }

    /**
     * Last-resort addresses for hosts whose DNS is commonly poisoned. Tried
     * after the resolved address fails; TLS still verifies the real name.
     */
    private val PINNED: Map<String, List<String>> = mapOf(
        "api.github.com" to listOf("140.82.121.6", "140.82.112.6", "140.82.113.6"),
        "github.com" to listOf("140.82.121.3", "140.82.112.3", "140.82.113.3"),
        "raw.githubusercontent.com" to GITHUB_CONTENT,
        "objects.githubusercontent.com" to GITHUB_CONTENT,
        "release-assets.githubusercontent.com" to GITHUB_CONTENT,
    )

    private val GITHUB_CONTENT: List<String>
        get() = listOf("185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133")

    /** Buffers the whole body (up to [Request.maxBytes]). */
    @Throws(IOException::class)
    fun request(req: Request): Response =
        stream(req) { status, headers, body, _, finalUrl ->
            val out = ByteArrayOutputStream()
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = body.read(buf)
                if (n <= 0) break
                out.write(buf, 0, n)
                if (out.size() > req.maxBytes) throw IOException("response too large")
            }
            Response(status, headers, out.toByteArray(), finalUrl)
        }

    /**
     * Performs the request, following redirects, and hands the final response
     * body to [handler] while the connection is still open.
     */
    @Throws(IOException::class)
    fun <T> stream(
        req: Request,
        handler: (status: Int, headers: Map<String, String>, body: InputStream, length: Long, finalUrl: String) -> T,
    ): T {
        var url = req.url
        var connectAddr = req.connectAddr
        repeat(req.maxRedirects + 1) {
            val uri = URI(url)
            val secure = when (uri.scheme?.lowercase()) {
                "https" -> true
                "http" -> false
                else -> throw IOException("unsupported URL: $url")
            }
            val host = uri.host ?: throw IOException("no host in $url")
            val port = if (uri.port > 0) uri.port else if (secure) 443 else 80
            val path = (uri.rawPath?.ifEmpty { "/" } ?: "/") +
                (uri.rawQuery?.let { "?$it" } ?: "")

            val socket = open(host, port, secure, connectAddr, req)
            try {
                val stream = SocketStream(socket, 16 * 1024)
                val hostHeader = if (port == 443 || port == 80) host else "$host:$port"
                val sb = StringBuilder()
                sb.append("GET ").append(path).append(" HTTP/1.1\r\n")
                sb.append("Host: ").append(hostHeader).append("\r\n")
                sb.append("User-Agent: tg-ws-proxy-android\r\n")
                sb.append("Accept-Encoding: identity\r\n")
                sb.append("Connection: close\r\n")
                for ((k, v) in req.headers) sb.append(k).append(": ").append(v).append("\r\n")
                sb.append("\r\n")
                stream.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
                stream.flush()

                val statusLine = stream.readLine()?.trim() ?: throw EOFException("no response")
                val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull()
                    ?: throw IOException("bad status line: ${statusLine.take(60)}")
                val headers = HashMap<String, String>()
                while (true) {
                    val line = stream.readLine()?.trimEnd('\r') ?: break
                    if (line.isEmpty()) break
                    val i = line.indexOf(':')
                    if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
                    if (headers.size > 100) break
                }

                if (status in 300..399 && headers["location"] != null) {
                    url = uri.resolve(headers["location"]).toString()
                    connectAddr = null
                    return@repeat
                }

                val length = headers["content-length"]?.toLongOrNull() ?: -1L
                val body: InputStream = when {
                    headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true ->
                        ChunkedInput(stream)
                    length >= 0 -> BoundedInput(stream, length)
                    else -> BoundedInput(stream, Long.MAX_VALUE)
                }
                return handler(status, headers, body, length, url)
            } finally {
                runCatching { socket.close() }
            }
        }
        throw IOException("too many redirects for ${req.url}")
    }

    private fun open(host: String, port: Int, secure: Boolean, connectAddr: String?, req: Request): Socket {
        val candidates = ArrayList<String>()
        if (connectAddr != null) candidates.add(connectAddr)
        else if (req.useDns) candidates.add(host)
        PINNED[host.lowercase()]?.let { candidates.addAll(it) }
        if (candidates.isEmpty()) throw IOException("no address for $host")

        var last: Exception? = null
        for (addr in candidates.distinct()) {
            try {
                return if (secure) {
                    Tls.connect(
                        host = addr, port = port, sni = host,
                        connectTimeoutMs = minOf(req.timeoutMs, 8_000),
                        readTimeoutMs = req.timeoutMs,
                        bufferSize = 128 * 1024,
                        fragmentHandshake = false,
                        verify = Tls.Verify.FULL,
                        forceVerify = true,
                    )
                } else {
                    Tls.connectPlain(addr, port, minOf(req.timeoutMs, 8_000), 128 * 1024).also {
                        it.soTimeout = req.timeoutMs
                    }
                }
            } catch (e: Exception) {
                last = e
                Logger.d("HTTP connect to $host via $addr failed: $e")
            }
        }
        throw (last as? IOException) ?: IOException(last)
    }

    private class BoundedInput(private val s: SocketStream, private var left: Long) : InputStream() {
        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) <= 0) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (left <= 0) return -1
            val n = s.read(b, off, minOf(len.toLong(), left).toInt())
            if (n <= 0) return -1
            left -= n
            return n
        }
    }

    private class ChunkedInput(private val s: SocketStream) : InputStream() {
        private var chunkLeft = 0L
        private var done = false

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) <= 0) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (done) return -1
            if (chunkLeft == 0L) {
                val line = s.readLine()?.trim() ?: return -1
                val size = line.substringBefore(';').trim().toLongOrNull(16)
                    ?: throw IOException("bad chunk header")
                if (size == 0L) {
                    done = true
                    return -1
                }
                chunkLeft = size
            }
            val n = s.read(b, off, minOf(len.toLong(), chunkLeft).toInt())
            if (n <= 0) return -1
            chunkLeft -= n
            if (chunkLeft == 0L) s.readLine() // CRLF after the chunk
            return n
        }
    }
}
