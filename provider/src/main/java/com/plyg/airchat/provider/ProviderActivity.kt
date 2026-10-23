package com.plyg.airchat.provider

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.plyg.airchat.core.PathClass

/** The provider's one screen: start or stop it, and how much it carries, never whom (AP-8). */
class ProviderActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val runtime = (application as ProviderApplication).runtime
        setContent {
            val context = LocalContext.current
            val dark = isSystemInDarkTheme()
            val colors = when {
                Build.VERSION.SDK_INT < 31 -> if (dark) darkColorScheme() else lightColorScheme()
                dark -> dynamicDarkColorScheme(context)
                else -> dynamicLightColorScheme(context)
            }
            MaterialTheme(colorScheme = colors) {
                Surface(Modifier.fillMaxSize()) { ProviderScreen(runtime) }
            }
        }
    }

    @Composable
    private fun ProviderScreen(runtime: ProviderRuntime) {
        val state by runtime.state.collectAsStateWithLifecycle()
        val status by runtime.airProvider.status.collectAsStateWithLifecycle()
        val start = {
            runtime.wanted = true
            ProviderService.start(this)
        }
        val permissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
            if (runtime.missingPermissions().isEmpty()) start()
        }
        Column(
            Modifier.safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
            Text(stringResource(R.string.explainer), style = MaterialTheme.typography.bodyLarge)
            if (!runtime.supported) {
                Text(stringResource(R.string.unsupported), color = MaterialTheme.colorScheme.error)
                return@Column
            }
            val carrying = when {
                !state.running -> stringResource(R.string.stopped)
                status.cannotRun && status.hot -> stringResource(R.string.waiting_hot)
                status.cannotRun -> stringResource(R.string.waiting_battery, status.batteryPercent)
                PathClass.VIDEO in status.classes -> stringResource(R.string.carrying_all)
                else -> stringResource(R.string.carrying_voice, status.batteryPercent)
            }
            Text(carrying, style = MaterialTheme.typography.titleMedium)
            if (state.running) {
                Text(pluralStringResource(R.plurals.neighbours, state.neighbours, state.neighbours))
                Text(pluralStringResource(R.plurals.paths, state.paths, state.paths))
            }
            if (state.running) {
                OutlinedButton(
                    onClick = {
                        runtime.wanted = false
                        ProviderService.stop(this@ProviderActivity)
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.stop)) }
            } else {
                Button(
                    onClick = {
                        val missing = runtime.missingPermissions()
                        if (missing.isEmpty()) start() else permissions.launch(missing.toTypedArray())
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.start)) }
            }
            Text(
                stringResource(R.string.keep_charging),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
