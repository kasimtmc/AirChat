package com.plyg.airchat

import android.app.Application
import com.plyg.airchat.runtime.AirChatRuntime
import com.plyg.airchat.ui.SensitiveClipboard

class AirChatApplication : Application() {
    lateinit var runtime: AirChatRuntime
        private set

    /** What is copied in the app: marked sensitive, cleared after a while (requirement S-9). */
    lateinit var clipboard: SensitiveClipboard
        private set

    override fun onCreate() {
        super.onCreate()
        runtime = AirChatRuntime(this)
        clipboard = SensitiveClipboard(this)
    }
}
