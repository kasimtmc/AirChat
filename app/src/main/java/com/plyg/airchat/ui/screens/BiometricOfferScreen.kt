package com.plyg.airchat.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import com.plyg.airchat.R
import com.plyg.airchat.ui.UiState

@Composable
fun BiometricOfferScreen(state: UiState, onEnable: () -> Unit, onSkip: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        ScreenHeader(
            R.drawable.ic_fingerprint,
            stringResource(R.string.biometric_offer_title),
            stringResource(R.string.biometric_offer_body),
        )
        Spacer(Modifier.height(8.dp))
        ErrorText(state.error)
        BusyButton(R.string.enable, busy = state.busy, onClick = onEnable)
        TextButton(onClick = onSkip, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.not_now))
        }
    }
}
