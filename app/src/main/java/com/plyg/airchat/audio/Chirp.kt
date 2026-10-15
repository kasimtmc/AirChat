package com.plyg.airchat.audio

import kotlin.math.PI
import kotlin.math.min
import kotlin.math.sin
import kotlin.random.Random

/**
 * The short walkie-talkie sound that opens a push-to-talk turn: a burst of squelch, then a rising
 * two-tone beep. Made here, so no sound file ships with the app.
 */
object Chirp {
    /** How long it lasts; the talker's first captured audio is dropped for as long. */
    const val DURATION_MS = 160

    /** 16-bit mono PCM at [rate] Hz, little endian. */
    fun pcm(rate: Int): ByteArray {
        val squelch = rate * 40 / 1000
        val low = rate * 55 / 1000
        val high = rate * 65 / 1000
        val samples = squelch + low + high
        val out = ByteArray(samples * 2)
        val random = Random(7)
        for (i in 0 until samples) {
            val value = when {
                i < squelch -> random.nextDouble(-1.0, 1.0) * 0.18 * (1.0 - i.toDouble() / squelch)
                i < squelch + low -> tone(i - squelch, low, rate, 1_250.0)
                else -> tone(i - squelch - low, high, rate, 1_650.0)
            }
            val sample = (value * Short.MAX_VALUE).toInt().coerceIn(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt())
            out[2 * i] = sample.toByte()
            out[2 * i + 1] = (sample shr 8).toByte()
        }
        return out
    }

    /** A sine at [hz], faded in and out over 5 ms so it does not click. */
    private fun tone(index: Int, length: Int, rate: Int, hz: Double): Double {
        val ramp = rate * 5 / 1000
        val envelope = min(1.0, min(index, length - 1 - index).toDouble() / ramp)
        return 0.35 * envelope * sin(2 * PI * hz * index / rate)
    }
}
