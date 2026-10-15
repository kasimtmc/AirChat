package com.plyg.airchat.ui.screens

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.editableText
import androidx.compose.ui.semantics.focused
import androidx.compose.ui.semantics.isEditable
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.onImeAction
import androidx.compose.ui.semantics.password
import androidx.compose.ui.semantics.requestFocus
import androidx.compose.ui.semantics.setText
import androidx.compose.ui.semantics.textSelectionRange
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType

private const val MASK = '•'

/**
 * PIN or passphrase entry. The text is obscured on screen, cannot be copied out of the field, and is
 * never exposed to accessibility or autofill services.
 *
 * Compose reports a text field's real text to accessibility services even when it is drawn
 * obscured, so any app holding the accessibility permission could read the PIN. The field's own
 * semantics are therefore replaced with an equivalent node whose text is only a mask of the same
 * length; focus, typing, `setText` and the IME action keep working for TalkBack users.
 */
@Composable
fun PinField(
    state: TextFieldState,
    @StringRes label: Int,
    passphrase: Boolean,
    imeAction: ImeAction,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onDone: () -> Unit = {},
) {
    val labelText = stringResource(label)
    val focusManager = LocalFocusManager.current
    val focusRequester = remember { FocusRequester() }
    var hasFocus by remember { mutableStateOf(false) }
    val runImeAction = {
        if (imeAction == ImeAction.Done) onDone() else focusManager.moveFocus(FocusDirection.Next)
    }

    Box(
        modifier.clearAndSetSemantics {
            contentDescription = labelText
            password()
            editableText = AnnotatedString(MASK.toString().repeat(state.text.length))
            textSelectionRange = TextRange(state.selection.end)
            isEditable = enabled
            focused = hasFocus
            if (enabled) {
                onClick { focusRequester.requestFocus(); true }
                requestFocus { focusRequester.requestFocus(); true }
                setText { text ->
                    state.setTextAndPlaceCursorAtEnd(text.text)
                    true
                }
                onImeAction(imeAction) {
                    runImeAction()
                    true
                }
            } else {
                disabled()
            }
        },
    ) {
        OutlinedSecureTextField(
            state = state,
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(focusRequester)
                .onFocusChanged { hasFocus = it.isFocused },
            enabled = enabled,
            label = { Text(labelText) },
            keyboardOptions = KeyboardOptions(
                keyboardType = if (passphrase) KeyboardType.Password else KeyboardType.NumberPassword,
                imeAction = imeAction,
                autoCorrectEnabled = false,
            ),
            onKeyboardAction = { if (imeAction == ImeAction.Done) onDone() else it() },
        )
    }
}
