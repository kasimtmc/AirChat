package com.plyg.airchat.ui

import androidx.annotation.StringRes
import com.plyg.airchat.R
import com.plyg.airchat.net.TransportKind

@get:StringRes
val TransportKind.label: Int
    get() = when (this) {
        TransportKind.LAN -> R.string.transport_lan
        TransportKind.AWARE -> R.string.transport_aware
        TransportKind.HOTSPOT -> R.string.transport_hotspot
        TransportKind.RELAY -> R.string.transport_relay
        TransportKind.BLE -> R.string.transport_ble
    }
