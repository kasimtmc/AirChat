package com.plyg.airchat.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import com.plyg.airchat.R
import com.plyg.airchat.ui.UiState

@Composable
fun OnboardingScreen(
    state: UiState,
    onCreate: (displayName: String, pin: CharSequence, confirmation: CharSequence) -> Unit,
) {
    val name = rememberTextFieldState()
    val pin = rememberTextFieldState()
    val confirmation = rememberTextFieldState()
    var passphrase by rememberSaveable { mutableStateOf(false) }
    val submit = {
        onCreate(name.text.toString(), pin.text, confirmation.text)
        pin.clearText()
        confirmation.clearText()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(24.dp))
        ScreenHeader(R.drawable.ic_chat, stringResource(R.string.onboarding_title), stringResource(R.string.onboarding_subtitle))
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            state = name,
            modifier = Modifier.fillMaxWidth(),
            enabled = !state.busy,
            label = { Text(stringResource(R.string.display_name)) },
            lineLimits = TextFieldLineLimits.SingleLine,
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Words,
                autoCorrectEnabled = false,
                imeAction = ImeAction.Next,
            ),
        )
        PinField(pin, R.string.pin, passphrase, ImeAction.Next, Modifier.fillMaxWidth(), !state.busy)
        PinField(confirmation, R.string.pin_confirm, passphrase, ImeAction.Done, Modifier.fillMaxWidth(), !state.busy, submit)
        TextButton(onClick = { passphrase = !passphrase }) {
            Text(stringResource(if (passphrase) R.string.use_numeric_pin else R.string.use_passphrase))
        }
        NoticeCard(R.drawable.ic_lock, stringResource(R.string.pin_unrecoverable_warning), warning = true)
        ErrorText(state.error)
        BusyButton(R.string.create_account, busy = state.busy, onClick = submit)
    }
}
