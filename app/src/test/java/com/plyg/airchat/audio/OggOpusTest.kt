package com.plyg.airchat.audio

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class OggOpusTest {
    /** A 20 ms Opus packet of silence (CELT, full band). */
    private val silence = byteArrayOf(0xf8.toByte(), 0xff.toByte(), 0xfe.toByte())

    @Test
    fun pagesCarryTheHeadersAndThePacketsWithValidChecksums() {
        val packets = List(120) { silence.copyOf() }
        val file = OggOpus.mux(packets, 16_000)
        val pages = pages(file)
        // OpusHead, OpusTags, then 50 + 50 + 20 packets.
        assertEquals(5, pages.size)
        assertArrayEquals("OpusHead".toByteArray(), pages[0].body.copyOf(8))
        assertArrayEquals("OpusTags".toByteArray(), pages[1].body.copyOf(8))
        assertEquals(0x02, pages[0].flags)
        assertEquals(0x04, pages.last().flags)
        assertEquals(120L * 960, pages.last().granule)
        assertEquals(listOf(50, 50, 20), pages.drop(2).map { it.segments })
        assertEquals(2_400L, OggOpus.durationMs(120))
        // For a look with opusinfo or ffprobe: AIRCHAT_OGG_OUT=/tmp/x.ogg ./gradlew :app:testDebugUnitTest
        System.getenv("AIRCHAT_OGG_OUT")?.let { File(it).writeBytes(file) }
    }

    @Test
    fun theChecksumIsOggs() {
        // CRC of "123456789" with Ogg's parameters (CRC-32/MPEG-2 without the initial ones).
        assertEquals(0x89A1897F.toInt(), OggOpus.crc("123456789".toByteArray()))
    }

    private class Page(val flags: Int, val granule: Long, val segments: Int, val body: ByteArray)

    private fun pages(file: ByteArray): List<Page> {
        val pages = mutableListOf<Page>()
        var at = 0
        while (at < file.size) {
            assertArrayEquals("OggS".toByteArray(), file.copyOfRange(at, at + 4))
            val flags = file[at + 5].toInt()
            var granule = 0L
            for (i in 0 until 8) granule = granule or ((file[at + 6 + i].toLong() and 0xff) shl (8 * i))
            val count = file[at + 26].toInt() and 0xff
            val lacing = file.copyOfRange(at + 27, at + 27 + count)
            val length = lacing.sumOf { it.toInt() and 0xff }
            val end = at + 27 + count + length
            val page = file.copyOfRange(at, end)
            val stored = page.copyOfRange(22, 26)
            for (i in 22 until 26) page[i] = 0
            val crc = OggOpus.crc(page)
            assertArrayEquals(ByteArray(4) { (crc ushr (8 * it)).toByte() }, stored)
            pages += Page(flags, granule, lacing.count { (it.toInt() and 0xff) < 255 }, file.copyOfRange(at + 27 + count, end))
            at = end
        }
        return pages
    }
}
