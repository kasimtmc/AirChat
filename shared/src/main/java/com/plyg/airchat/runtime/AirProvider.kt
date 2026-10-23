package com.plyg.airchat.runtime

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.BatteryManager
import android.os.PowerManager
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import com.plyg.airchat.core.PathClass
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Air Provider mode (requirements AP-1, AP-5): off unless the user turns it on. While on, this
 * device carries other devices' calls, video and files over paths (rust/airchat-protocol/docs/protocol.md §12), and what
 * it carries follows its own state: everything while charging or above 50 % battery, calls and
 * push-to-talk only from 20 %, nothing below 20 % or when hot, and the mode then turns itself off.
 * Only on a device with Wi-Fi Aware (AP-1): a provider must be found as far as Wi-Fi reaches.
 * Main thread only.
 */
class AirProvider(app: Application, private val settings: SharedPreferences) {
    data class Status(
        /** The device has Wi-Fi Aware; without it the mode is not offered. */
        val supported: Boolean = true,
        val enabled: Boolean = false,
        /** What this device carries for others now; empty while off. */
        val classes: List<PathClass> = emptyList(),
        val batteryPercent: Int = 100,
        val charging: Boolean = false,
        val hot: Boolean = false,
    ) {
        /** Too low or too hot to carry anything: the mode cannot be turned on now. */
        val cannotRun: Boolean get() = hot || (!charging && batteryPercent < LOW_PERCENT)
    }

    private val supported = app.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)
    private val _status = MutableStateFlow(
        Status(supported = supported, enabled = supported && settings.getBoolean(KEY_ENABLED, false)),
    )
    val status: StateFlow<Status> = _status

    /** The mode turned itself off: the battery ran low or the device got hot. */
    var onStoppedItself: () -> Unit = {}

    init {
        // Turned on before the mode needed Wi-Fi Aware.
        if (!supported) settings.edit { putBoolean(KEY_ENABLED, false) }
        val battery = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) = onBattery(intent)
        }
        // Sticky: the current state comes back at once.
        ContextCompat.registerReceiver(app, battery, IntentFilter(Intent.ACTION_BATTERY_CHANGED), ContextCompat.RECEIVER_NOT_EXPORTED)
            ?.let(::onBattery)
        app.getSystemService(PowerManager::class.java)?.let { power ->
            onThermal(power.currentThermalStatus)
            power.addThermalStatusListener(ContextCompat.getMainExecutor(app), ::onThermal)
        }
    }

    /** Turns the mode on or off; it stays off while the device cannot run it, or never could. */
    fun setEnabled(enabled: Boolean) {
        val on = enabled && supported && !_status.value.cannotRun
        settings.edit { putBoolean(KEY_ENABLED, on) }
        update(_status.value.copy(enabled = on))
    }

    private fun onBattery(intent: Intent) {
        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, 100)
        val percent = if (level >= 0 && scale > 0) level * 100 / scale else 100
        val charging = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0
        update(_status.value.copy(batteryPercent = percent, charging = charging))
    }

    private fun onThermal(status: Int) = update(_status.value.copy(hot = status >= PowerManager.THERMAL_STATUS_SEVERE))

    private fun update(next: Status) {
        val stops = next.enabled && next.cannotRun
        val enabled = next.enabled && next.supported && !stops
        val classes = when {
            !enabled -> emptyList()
            next.charging || next.batteryPercent > HALF_PERCENT -> listOf(PathClass.VOICE, PathClass.VIDEO, PathClass.FILES)
            else -> listOf(PathClass.VOICE)
        }
        _status.value = next.copy(enabled = enabled, classes = classes)
        if (stops) {
            settings.edit { putBoolean(KEY_ENABLED, false) }
            onStoppedItself()
        }
    }

    private companion object {
        const val KEY_ENABLED = "air_provider"
        const val LOW_PERCENT = 20
        const val HALF_PERCENT = 50
    }
}
