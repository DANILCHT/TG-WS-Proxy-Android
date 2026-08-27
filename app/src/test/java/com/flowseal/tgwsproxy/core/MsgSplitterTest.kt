package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.core.Crypto.CtrStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kotlin port of tests/test_bridge.py. */
class MsgSplitterTest {

    private fun relayInit(): ByteArray = Crypto.randomBytes(64)

    private fun encryptor(relayInit: ByteArray): CtrStream =
        CtrStream(relayInit.copyOfRange(8, 40), relayInit.copyOfRange(40, 56))
            .also { it.skip(64) }

    private fun abridged(payload: ByteArray): ByteArray {
        val words = payload.size / 4
        return if (words < 0x7F) {
            byteArrayOf(words.toByte()) + payload
        } else {
            byteArrayOf(0x7F) + byteArrayOf(
                (words and 0xFF).toByte(),
                ((words shr 8) and 0xFF).toByte(),
                ((words shr 16) and 0xFF).toByte(),
            ) + payload
        }
    }

    private fun intermediate(payload: ByteArray): ByteArray {
        val n = payload.size
        return byteArrayOf(
            (n and 0xFF).toByte(),
            ((n shr 8) and 0xFF).toByte(),
            ((n shr 16) and 0xFF).toByte(),
            ((n shr 24) and 0xFF).toByte(),
        ) + payload
    }

    private class Split(
        val splitter: MsgSplitter,
        val stream: ByteArray,
        val parts: List<ByteArray>,
    )

    private fun split(
        protoInt: Int,
        packets: List<ByteArray>,
        chunkSizes: List<Int>? = null,
    ): Split {
        val init = relayInit()
        val splitter = MsgSplitter(init, protoInt)
        val enc = encryptor(init)
        var plain = ByteArray(0)
        for (p in packets) plain += p
        val stream = enc.update(plain)

        val chunks = ArrayList<ByteArray>()
        if (chunkSizes == null) {
            chunks.add(stream)
        } else {
            var offset = 0
            for (size in chunkSizes) {
                val end = minOf(offset + size, stream.size)
                chunks.add(stream.copyOfRange(offset, end))
                offset = end
            }
            if (offset < stream.size) chunks.add(stream.copyOfRange(offset, stream.size))
        }

        val parts = ArrayList<ByteArray>()
        for (c in chunks) parts.addAll(splitter.split(c))
        return Split(splitter, stream, parts)
    }

    private fun join(parts: List<ByteArray>): ByteArray {
        var out = ByteArray(0)
        for (p in parts) out += p
        return out
    }

    @Test
    fun abridgedStreamSplitsIntoPackets() {
        val packets = listOf(
            abridged(ByteArray(4) { 'a'.code.toByte() }),
            abridged(ByteArray(16) { 'b'.code.toByte() }),
            abridged(ByteArray(40) { 'c'.code.toByte() }),
        )
        val r = split(Const.PROTO_ABRIDGED_INT, packets)
        assertEquals(3, r.parts.size)
        assertTrue(join(r.parts).contentEquals(r.stream))
        assertEquals(listOf(5, 17, 41), r.parts.map { it.size })
    }

    @Test
    fun intermediateStreamSplitsIntoPackets() {
        val packets = listOf(
            intermediate(ByteArray(8) { 'a'.code.toByte() }),
            intermediate(ByteArray(12) { 'b'.code.toByte() }),
        )
        val r = split(Const.PROTO_INTERMEDIATE_INT, packets)
        assertEquals(2, r.parts.size)
        assertTrue(join(r.parts).contentEquals(r.stream))
    }

    @Test
    fun paddedIntermediateUsesIntermediateFraming() {
        val packets = listOf(intermediate(ByteArray(20) { 'z'.code.toByte() }))
        val r = split(Const.PROTO_PADDED_INTERMEDIATE_INT, packets)
        assertEquals(1, r.parts.size)
        assertTrue(r.parts[0].contentEquals(r.stream))
    }

    @Test
    fun partialPacketIsBufferedUntilComplete() {
        val packet = abridged(ByteArray(20) { 'a'.code.toByte() })
        val r = split(
            Const.PROTO_ABRIDGED_INT, listOf(packet),
            chunkSizes = List(packet.size - 1) { 1 },
        )
        assertEquals(1, r.parts.size)
        assertTrue(r.parts[0].contentEquals(r.stream))
    }

    @Test
    fun splitPreservesStreamAcrossArbitraryChunking() {
        val packets = (0 until 8).map { i ->
            intermediate(ByteArray(16) { i.toByte() })
        }
        val r = split(Const.PROTO_INTERMEDIATE_INT, packets, chunkSizes = listOf(7, 3, 50, 11))
        assertTrue(join(r.parts).contentEquals(r.stream))
        assertEquals(8, r.parts.size)
    }

    @Test
    fun emptyChunkYieldsNothing() {
        val splitter = MsgSplitter(relayInit(), Const.PROTO_INTERMEDIATE_INT)
        assertTrue(splitter.split(ByteArray(0)).isEmpty())
    }

    @Test
    fun zeroLengthPacketDisablesSplitting() {
        val init = relayInit()
        val splitter = MsgSplitter(init, Const.PROTO_INTERMEDIATE_INT)
        val enc = encryptor(init)
        val stream = enc.update(byteArrayOf(0, 0, 0, 0) + "tail".toByteArray())
        val parts = splitter.split(stream)
        assertEquals(1, parts.size)
        assertTrue(parts[0].contentEquals(stream))

        val raw = "raw".toByteArray()
        val after = splitter.split(raw)
        assertEquals(1, after.size)
        assertTrue(after[0].contentEquals(raw))
    }

    @Test
    fun flushReturnsBufferedTailOnce() {
        val init = relayInit()
        val splitter = MsgSplitter(init, Const.PROTO_INTERMEDIATE_INT)
        val enc = encryptor(init)
        val full = intermediate(ByteArray(32) { 'x'.code.toByte() })
        val partial = enc.update(full, 0, 10)
        assertTrue(splitter.split(partial).isEmpty())
        val flushed = splitter.flush()
        assertEquals(1, flushed.size)
        assertTrue(flushed[0].contentEquals(partial))
        assertTrue(splitter.flush().isEmpty())
    }
}
