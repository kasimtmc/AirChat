package com.plyg.airchat.runtime

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.plyg.airchat.AirChatApplication

/**
 * Keeps the process alive while AirChat is in the background or locked, so links to nearby contacts
 * stay up and messages keep arriving. It holds no logic: [AirChatRuntime] does the work.
 */
class AirChatService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val runtime = (application as AirChatApplication).runtime
        // While a call or talk uses the microphone, the service says so (Android 11+ requires it
        // for the microphone to keep working in the background).
        val microphone = intent?.getBooleanExtra(EXTRA_MICROPHONE, false) == true && Build.VERSION.SDK_INT >= 30
        val types = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or
            (if (microphone) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0)
        ServiceCompat.startForeground(this, Notifications.ID_BACKGROUND, runtime.notifications.background(), types)
        // After the process was killed nothing can run until the user unlocks again.
        if (runtime.account == null) stopSelf()
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val EXTRA_MICROPHONE = "microphone"

        fun start(context: Context, microphone: Boolean = false) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, AirChatService::class.java).putExtra(EXTRA_MICROPHONE, microphone),
            )
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, AirChatService::class.java))
        }
    }
}
