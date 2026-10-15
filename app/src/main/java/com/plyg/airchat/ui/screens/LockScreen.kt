package com.plyg.airchat.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.ui.res.painterResource
import com.plyg.airchat.R
import com.plyg.airchat.ui.UiState

@Composable
fun LockScreen(
    state: UiState,
    onUnlock: (CharSequence) -> Unit,
    onBiometric: () -> Unit,
    onReset: () -> Unit,
) {
    val pin = rememberTextFieldState()
    var passphrase by rememberSaveable { mutableStateOf(false) }
    var confirmReset by rememberSaveable { mutableStateOf(false) }
    val canUseBiometric = state.biometricEnabled && state.biometricAvailable
    val lockedOut = state.lockoutSeconds > 0
    val submit = {
        if (!lockedOut) onUnlock(pin.text)
        pin.clearText()
    }

    // Offer the fingerprint right away; the PIN stays available underneath.
    LaunchedEffect(Unit) { if (canUseBiometric) onBiometric() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .imePadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        ScreenHeader(R.drawable.ic_lock, stringResource(R.string.locked_title))
        Spacer(Modifier.height(8.dp))
        PinField(pin, R.string.pin, passphrase, ImeAction.Done, Modifier.fillMaxWidth(), !state.busy, submit)
        TextButton(onClick = { passphrase = !passphrase }) {
            Text(stringResource(if (passphrase) R.string.use_numeric_pin else R.string.use_passphrase))
        }
        if (lockedOut) {
            Text(
                stringResource(R.string.lockout, state.lockoutSeconds),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        } else {
            ErrorText(state.error)
        }
        BusyButton(R.string.unlock, busy = state.busy, onClick = submit, enabled = !lockedOut)
        if (canUseBiometric) {
            OutlinedButton(onClick = onBiometric, enabled = !state.busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Icon(painterResource(R.drawable.ic_fingerprint), contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.unlock_with_biometric))
            }
        }
        TextButton(onClick = { confirmReset = true }, enabled = !state.busy) {
            Text(stringResource(R.string.forgot_pin))
        }
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text(stringResource(R.string.reset_title)) },
            text = { Text(stringResource(R.string.reset_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    onReset()
                }) {
                    Text(stringResource(R.string.reset_confirm), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmReset = false }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }
}
