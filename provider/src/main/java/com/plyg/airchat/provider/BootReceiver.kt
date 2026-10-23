package com.plyg.airchat.provider

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Starts the provider with the phone, if the user started it and has not stopped it (AP-8). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val runtime = (context.applicationContext as ProviderApplication).runtime
        if (runtime.wanted) ProviderService.start(context)
    }
}
