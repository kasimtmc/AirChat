package com.plyg.airchat.audio

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * Wraps Opus packets in an Ogg file (RFC 7845), in memory, so a voice message plays with the
 * platform's player. Packets are 20 ms each, as [VoiceEngine] makes them.
 */
object OggOpus {
    /** Samples per packet at the 48 kHz Ogg Opus counts in. */
    private const val SAMPLES_PER_PACKET = 960

    /** The encoder's look-ahead, which the player drops at the start (RFC 7845 §4.2). */
    private const val PRE_SKIP = 312

    /** About a second of audio per page. */
    private const val PACKETS_PER_PAGE = 50

    /** The file of [packets] recorded at [inputRate] Hz, mono. */
    fun mux(packets: List<ByteArray>, inputRate: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val serial = SecureRandom().nextInt()
        var sequence = 0
        val head = ByteArrayOutputStream().apply {
            write("OpusHead".toByteArray())
            write(1) // version
            write(1) // channels
            writeLe(PRE_SKIP.toLong(), 2)
            writeLe(inputRate.toLong(), 4)
            writeLe(0, 2) // output gain
            write(0) // channel mapping family: mono or stereo
        }.toByteArray()
        page(out, listOf(head), granule = 0, serial, sequence++, first = true, last = false)
        val vendor = "AirChat".toByteArray()
        val tags = ByteArrayOutputStream().apply {
            write("OpusTags".toByteArray())
            writeLe(vendor.size.toLong(), 4)
            write(vendor)
            writeLe(0, 4) // no comments
        }.toByteArray()
        page(out, listOf(tags), granule = 0, serial, sequence++, first = false, last = packets.isEmpty())
        var done = 0
        for (chunk in packets.chunked(PACKETS_PER_PAGE)) {
            done += chunk.size
            val last = done == packets.size
            page(out, chunk, granule = done.toLong() * SAMPLES_PER_PACKET, serial, sequence++, first = false, last = last)
        }
        return out.toByteArray()
    }

    /** How long a file of [packets] packets plays, in ms. */
    fun durationMs(packets: Int): Long = packets * 20L

    private fun page(
        out: ByteArrayOutputStream,
        packets: List<ByteArray>,
        granule: Long,
        serial: Int,
        sequence: Int,
        first: Boolean,
        last: Boolean,
    ) {
        // Each packet is laced in 255-byte segments and ends with a shorter one (maybe 0 bytes).
        val lacing = ByteArrayOutputStream()
        for (packet in packets) {
            var left = packet.size
            while (left >= 255) {
                lacing.write(255)
                left -= 255
            }
            lacing.write(left)
        }
        val segments = lacing.toByteArray()
        require(segments.size <= 255) { "too many segments for one page" }
        val page = ByteArrayOutputStream().apply {
            write("OggS".toByteArray())
            write(0) // version
            write((if (first) 0x02 else 0) or (if (last) 0x04 else 0))
            writeLe(granule, 8)
            writeLe(serial.toLong(), 4)
            writeLe(sequence.toLong(), 4)
            writeLe(0, 4) // checksum, filled in below
            write(segments.size)
            write(segments)
            packets.forEach(::write)
        }.toByteArray()
        val crc = crc(page)
        for (i in 0 until 4) page[22 + i] = (crc ushr (8 * i)).toByte()
        out.write(page)
    }

    private fun ByteArrayOutputStream.writeLe(value: Long, bytes: Int) {
        for (i in 0 until bytes) write((value ushr (8 * i)).toInt() and 0xff)
    }

    /** Ogg's CRC-32: polynomial 0x04C11DB7, no reflection, starting at 0. */
    private val table = IntArray(256) { index ->
        var r = index shl 24
        repeat(8) { r = if (r and Int.MIN_VALUE != 0) (r shl 1) xor 0x04C11DB7 else r shl 1 }
        r
    }

    internal fun crc(data: ByteArray): Int {
        var crc = 0
        for (b in data) crc = (crc shl 8) xor table[((crc ushr 24) xor (b.toInt() and 0xff)) and 0xff]
        return crc
    }
}
