package com.plyg.airchat.runtime

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.Ringtone
import android.media.RingtoneManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager

/** Rings and vibrates for an incoming call, as the phone's settings allow. */
class Ringer(private val context: Context) {
    private var ringtone: Ringtone? = null
    private val vibrator: Vibrator? =
        if (Build.VERSION.SDK_INT >= 31) {
            context.getSystemService(VibratorManager::class.java)?.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Vibrator::class.java)
        }

    fun start() {
        stop()
        val mode = context.getSystemService(AudioManager::class.java).ringerMode
        if (mode == AudioManager.RINGER_MODE_NORMAL) {
            ringtone = RingtoneManager.getRingtone(context, RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE))?.apply {
                audioAttributes = AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
                isLooping = true
                play()
            }
        }
        if (mode != AudioManager.RINGER_MODE_SILENT) {
            vibrator?.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 800, 1200), 0))
        }
    }

    fun stop() {
        ringtone?.stop()
        ringtone = null
        vibrator?.cancel()
    }
}
