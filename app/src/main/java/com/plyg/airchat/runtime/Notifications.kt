package com.plyg.airchat.runtime

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.plyg.airchat.MainActivity
import com.plyg.airchat.R

/**
 * AirChat's notifications. None of them ever names a contact or shows message content, also not on
 * the lock screen (requirement S-9): they only say that something arrived.
 */
class Notifications(private val context: Context) {
    private val manager = NotificationManagerCompat.from(context)
    private var unread = 0

    init {
        val system = context.getSystemService(NotificationManager::class.java)
        system.createNotificationChannel(
            NotificationChannel(CHANNEL_BACKGROUND, context.getString(R.string.channel_background), NotificationManager.IMPORTANCE_MIN)
                .apply { setShowBadge(false) },
        )
        system.createNotificationChannel(
            NotificationChannel(CHANNEL_MESSAGES, context.getString(R.string.channel_messages), NotificationManager.IMPORTANCE_HIGH)
                .apply { lockscreenVisibility = Notification.VISIBILITY_PRIVATE },
        )
        system.createNotificationChannel(
            NotificationChannel(CHANNEL_STATUS, context.getString(R.string.channel_status), NotificationManager.IMPORTANCE_DEFAULT),
        )
        // The app rings itself (Ringer), so the channel stays silent.
        system.createNotificationChannel(
            NotificationChannel(CHANNEL_CALLS, context.getString(R.string.channel_calls), NotificationManager.IMPORTANCE_HIGH).apply {
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setSound(null, null)
                enableVibration(false)
            },
        )
    }

    /**
     * An incoming call: opens AirChat full screen, also over the lock screen. Says only that a call
     * comes in, not from whom.
     */
    fun incomingCall() {
        if (!manager.areNotificationsEnabled()) return
        val open = openApp()
        val answer = PendingIntent.getActivity(
            context,
            REQUEST_ANSWER,
            Intent(context, MainActivity::class.java)
                .setAction(MainActivity.ACTION_ANSWER)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val decline = PendingIntent.getBroadcast(
            context,
            REQUEST_DECLINE,
            Intent(context, CallActionReceiver::class.java).setAction(CallActionReceiver.ACTION_DECLINE),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_CALLS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.incoming_call))
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setOngoing(true)
            .setContentIntent(open)
            .setFullScreenIntent(open, true)
            .addAction(0, context.getString(R.string.call_decline), decline)
            .addAction(0, context.getString(R.string.call_answer), answer)
            .build()
        try {
            manager.notify(ID_CALL, notification)
        } catch (_: SecurityException) {
        }
    }

    fun cancelCall() = manager.cancel(ID_CALL)

    /** The ongoing notification that keeps AirChat reachable while it is in the background. */
    fun background(): Notification =
        NotificationCompat.Builder(context, CHANNEL_BACKGROUND)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.background_title))
            .setContentText(context.getString(R.string.background_text))
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setContentIntent(openApp())
            .build()

    fun newMessage() {
        if (!manager.areNotificationsEnabled()) return
        unread++
        val text = context.resources.getQuantityString(R.plurals.new_messages, unread, unread)
        val generic = NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .build()
        val notification = NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(generic)
            .setAutoCancel(true)
            .setContentIntent(openApp())
            .build()
        try {
            manager.notify(ID_MESSAGES, notification)
        } catch (_: SecurityException) {
            // Permission revoked meanwhile.
        }
    }

    /** Someone asks to be added (rust/airchat-protocol/docs/protocol.md §4.8); who it is shows only inside the app. */
    fun contactRequest() {
        if (!manager.areNotificationsEnabled()) return
        val notification = NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.new_contact_request))
            .setCategory(NotificationCompat.CATEGORY_SOCIAL)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(openApp())
            .build()
        try {
            manager.notify(ID_REQUEST, notification)
        } catch (_: SecurityException) {
        }
    }

    /** Air Provider mode turned itself off (requirement AP-5): the battery ran low or the device got hot. */
    fun airProviderStopped() {
        if (!manager.areNotificationsEnabled()) return
        val notification = NotificationCompat.Builder(context, CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.air_provider))
            .setContentText(context.getString(R.string.air_provider_stopped))
            .setAutoCancel(true)
            .setContentIntent(openApp())
            .build()
        try {
            manager.notify(ID_STATUS, notification)
        } catch (_: SecurityException) {
        }
    }

    fun clearMessages() {
        unread = 0
        manager.cancel(ID_MESSAGES)
    }

    private fun openApp(): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
    )

    companion object {
        const val ID_BACKGROUND = 1
        private const val ID_MESSAGES = 2
        private const val ID_CALL = 3
        private const val ID_STATUS = 4
        private const val ID_REQUEST = 5
        private const val REQUEST_ANSWER = 1
        private const val REQUEST_DECLINE = 2
        private const val CHANNEL_CALLS = "calls"
        private const val CHANNEL_BACKGROUND = "background"
        private const val CHANNEL_MESSAGES = "messages"
        private const val CHANNEL_STATUS = "status"
    }
}
