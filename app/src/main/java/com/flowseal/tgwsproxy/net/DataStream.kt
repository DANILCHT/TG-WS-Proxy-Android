package com.flowseal.tgwsproxy.net

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

/**
 * Blocking byte stream abstraction that mirrors the pieces of asyncio's
 * StreamReader/StreamWriter pair this project uses. Implemented by the plain
 * client socket and by [FakeTlsStream].
 */
interface DataStream {
    /** Reads up to [len] bytes into [dest]; returns -1 on EOF. */
    fun read(dest: ByteArray, off: Int, len: Int): Int

    /** Reads exactly [n] bytes or throws [EOFException]. */
    fun readExactly(n: Int): ByteArray

    fun write(data: ByteArray, off: Int, len: Int)

    fun write(data: ByteArray) = write(data, 0, data.size)

    fun flush()

    fun close()

    /** Read timeout in ms for subsequent reads (0 = infinite). */
    fun setReadTimeout(ms: Int)
}

/**
 * Buffered stream over a socket. Keeps its own buffer so that [readExactly],
 * [readLine] and bulk [read] can be mixed without losing bytes.
 */
class SocketStream(
    private val socket: Socket,
    bufferSize: Int = 16 * 1024,
) : DataStream {

    private val input: InputStream = socket.getInputStream()
    private val output: OutputStream = socket.getOutputStream()
    private val buf = ByteArray(bufferSize)
    private var pos = 0
    private var limit = 0

    private fun buffered(): Int = limit - pos

    private fun fill(): Boolean {
        pos = 0
        limit = 0
        val n = input.read(buf, 0, buf.size)
        if (n <= 0) return false
        limit = n
        return true
    }

    override fun read(dest: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        val have = buffered()
        if (have > 0) {
            val n = minOf(have, len)
            System.arraycopy(buf, pos, dest, off, n)
            pos += n
            return n
        }
        return input.read(dest, off, len)
    }

    override fun readExactly(n: Int): ByteArray {
        val out = ByteArray(n)
        var read = 0
        while (read < n) {
            val have = buffered()
            if (have > 0) {
                val take = minOf(have, n - read)
                System.arraycopy(buf, pos, out, read, take)
                pos += take
                read += take
                continue
            }
            val got = input.read(out, read, n - read)
            if (got <= 0) throw EOFException("expected $n bytes, got $read")
            read += got
        }
        return out
    }

    /** Reads a line terminated by \n (inclusive), or null on EOF. */
    fun readLine(maxLen: Int = 1024): String? {
        val sb = StringBuilder()
        while (sb.length < maxLen) {
            if (buffered() == 0 && !fill()) {
                return if (sb.isEmpty()) null else sb.toString()
            }
            val b = buf[pos++]
            if (b == '\n'.code.toByte()) return sb.toString()
            sb.append((b.toInt() and 0xFF).toChar())
        }
        return sb.toString()
    }

    override fun write(data: ByteArray, off: Int, len: Int) {
        output.write(data, off, len)
    }

    override fun flush() {
        output.flush()
    }

    override fun close() {
        runCatching { socket.close() }
    }

    override fun setReadTimeout(ms: Int) {
        runCatching { socket.soTimeout = ms }
    }

    val rawSocket: Socket get() = socket
}
