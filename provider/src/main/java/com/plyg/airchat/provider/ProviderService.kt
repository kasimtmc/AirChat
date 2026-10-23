package com.plyg.airchat.provider

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat

/** Keeps the provider running in the background and after the screen goes off. */
class ProviderService : Service() {
    private val runtime get() = (application as ProviderApplication).runtime

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ServiceCompat.startForeground(this, ID, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        if (!runtime.wanted || runtime.missingPermissions().isNotEmpty()) {
            stopSelf()
            return START_NOT_STICKY
        }
        runtime.start()
        // Brought back by the system if it has to end the process.
        return START_STICKY
    }

    override fun onDestroy() {
        runtime.stop()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.channel_running), NotificationManager.IMPORTANCE_MIN)
                .apply { setShowBadge(false) },
        )
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, ProviderActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.running_title))
            .setContentText(getString(R.string.running_text))
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setContentIntent(open)
            .build()
    }

    companion object {
        private const val ID = 1
        private const val CHANNEL = "running"

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, ProviderService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ProviderService::class.java))
        }
    }
}
