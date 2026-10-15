package com.plyg.airchat

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import com.plyg.airchat.ui.AirChatApp
import com.plyg.airchat.ui.AppViewModel
import com.plyg.airchat.ui.BiometricPrompter
import com.plyg.airchat.ui.SensitiveCopies
import com.plyg.airchat.ui.theme.AirChatTheme

/** A [FragmentActivity] because the stable `BiometricPrompt` API needs one. */
class MainActivity : FragmentActivity() {
    companion object {
        /** "Answer" on the incoming-call notification. */
        const val ACTION_ANSWER = "com.plyg.airchat.action.ANSWER_CALL"
    }

    private val viewModel: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Blocks screenshots, screen recording and the recent-apps preview (requirement S-9).
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        val biometric = BiometricPrompter(this)
        val app = application as AirChatApplication
        setContent {
            AirChatTheme {
                SensitiveCopies(app.clipboard) {
                    AirChatApp(viewModel, biometric)
                }
            }
        }
        handle(intent)
        // A call comes in or goes on: show over the phone's lock screen and wake it. AirChat's own
        // lock still hides who calls.
        val voice = app.runtime.voice
        lifecycleScope.launch {
            voice.call.collect { call ->
                setShowWhenLocked(call != null)
                setTurnScreenOn(call != null)
            }
        }
        // Locked: what was copied in the app goes (requirement S-9).
        lifecycleScope.launch {
            app.runtime.locked.collect { locked -> if (locked) app.clipboard.locked() }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        if (intent?.action == ACTION_ANSWER) viewModel.answerRequested()
    }

    override fun onStart() {
        super.onStart()
        (application as AirChatApplication).runtime.onForeground()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // In front again (the clipboard can be read with focus only): a copy whose time ran out
        // in the background can be cleared now.
        if (hasFocus) (application as AirChatApplication).clipboard.clearIfOurs()
    }

    override fun onStop() {
        super.onStop()
        (application as AirChatApplication).runtime.onBackground()
    }
}
