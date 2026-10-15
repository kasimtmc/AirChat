package com.plyg.airchat.runtime

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.plyg.airchat.AirChatApplication

/** "Decline" on the incoming-call notification, without opening the app. */
class CallActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_DECLINE) (context.applicationContext as AirChatApplication).runtime.voice.hangUp()
    }

    companion object {
        const val ACTION_DECLINE = "com.plyg.airchat.action.DECLINE_CALL"
    }
}
