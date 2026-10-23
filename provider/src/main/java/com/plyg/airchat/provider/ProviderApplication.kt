package com.plyg.airchat.provider

import android.app.Application

class ProviderApplication : Application() {
    lateinit var runtime: ProviderRuntime
        private set

    override fun onCreate() {
        super.onCreate()
        runtime = ProviderRuntime(this)
    }
}
