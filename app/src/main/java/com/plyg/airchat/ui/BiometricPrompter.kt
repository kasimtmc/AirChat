package com.plyg.airchat.ui

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

/** Unlocks a Keystore-bound [Cipher] with a strong biometric. */
class BiometricPrompter(private val activity: FragmentActivity) {
    fun authenticate(
        cipher: Cipher,
        title: String,
        negativeButton: String,
        onSuccess: (Cipher) -> Unit,
        onFailure: () -> Unit = {},
    ) {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                result.cryptoObject?.cipher?.let(onSuccess) ?: onFailure()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onFailure()
        }
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setNegativeButtonText(negativeButton)
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
}
