package com.plyg.airchat.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * An AES-256-GCM key that lives in the Android Keystore and never leaves the device's secure hardware
 * (StrongBox when available, otherwise the TEE). Sealed blobs are `IV || ciphertext || tag`.
 */
class KeystoreKey private constructor(
    private val alias: String,
    private val configure: KeyGenParameterSpec.Builder.() -> Unit,
) {
    fun seal(plaintext: ByteArray): ByteArray = sealWith(encryptCipher(), plaintext)

    /** @throws KeyLostException if the key no longer exists, so [sealed] can never be opened. */
    fun open(sealed: ByteArray): ByteArray = openWith(decryptCipher(sealed), sealed)

    /** A cipher ready to encrypt. For [biometric] it must first be unlocked by `BiometricPrompt`. */
    fun encryptCipher(): Cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }

    /** A cipher ready to decrypt [sealed]. For [biometric] it must first be unlocked by `BiometricPrompt`. */
    fun decryptCipher(sealed: ByteArray): Cipher {
        require(sealed.size > IV_LENGTH) { "sealed blob too short" }
        val key = keyStore().getKey(alias, null) as SecretKey? ?: throw KeyLostException(alias)
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 0, IV_LENGTH))
        }
    }

    fun delete() {
        keyStore().deleteEntry(alias)
    }

    private fun key(): SecretKey = keyStore().getKey(alias, null) as SecretKey? ?: generate()

    private fun generate(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(strongBox)
            .apply(configure)
            .build()

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        return try {
            generator.init(spec(strongBox = true))
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            generator.init(spec(strongBox = false))
            generator.generateKey()
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
        private const val TAG_BITS = 128

        /**
         * Wraps the core's key records, binding them to this device's secure hardware.
         *
         * Deliberately not `setUnlockedDeviceRequired`: Android deletes such keys when the user removes
         * the phone's screen lock, which would make the account unopenable (verified on API 34).
         */
        fun device() = KeystoreKey("airchat.device") {}

        /** Protects the biometric unlock secret. Every use needs a strong biometric; new enrolments invalidate it. */
        fun biometric() = KeystoreKey("airchat.biometric") {
            setUserAuthenticationRequired(true)
            setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                setUserAuthenticationValidityDurationSeconds(-1)
            }
        }

        fun sealWith(cipher: Cipher, plaintext: ByteArray): ByteArray = cipher.iv + cipher.doFinal(plaintext)

        fun openWith(cipher: Cipher, sealed: ByteArray): ByteArray =
            cipher.doFinal(sealed, IV_LENGTH, sealed.size - IV_LENGTH)

        private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }
}

/** The Keystore key is gone (e.g. app data restored to another device); what it sealed is unrecoverable. */
class KeyLostException(alias: String) : Exception("Keystore key $alias no longer exists")
