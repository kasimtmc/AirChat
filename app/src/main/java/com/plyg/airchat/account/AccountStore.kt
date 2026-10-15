package com.plyg.airchat.account

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.AtomicFile
import com.plyg.airchat.core.Account
import com.plyg.airchat.core.CoreException
import com.plyg.airchat.core.accountExists
import com.plyg.airchat.core.createAccount
import com.plyg.airchat.security.KeyLostException
import com.plyg.airchat.security.KeystoreKey
import java.io.File
import javax.crypto.Cipher
import kotlin.math.min
import com.plyg.airchat.core.unlockWithPin as coreUnlockWithPin
import com.plyg.airchat.core.unlockWithSecret as coreUnlockWithSecret

/**
 * Creates and unlocks the account, and keeps the core's key records on disk wrapped with a
 * hardware-backed key (docs/architecture.md §4.2).
 *
 * Every function blocks (Argon2id, Keystore, disk); call them off the main thread.
 */
class AccountStore(context: Context) {
    /** Excluded from backups and device transfer by definition. */
    private val dir = File(context.noBackupFilesDir, "account").apply { mkdirs() }
    private val pinRecord = AtomicFile(File(dir, "pin.record"))
    private val biometricSecret = AtomicFile(File(dir, "biometric.secret"))
    private val biometricRecord = AtomicFile(File(dir, "biometric.record"))
    private val failedAttempts = AtomicFile(File(dir, "unlock.failures"))

    private val deviceKey = KeystoreKey.device()
    private val biometricKey = KeystoreKey.biometric()

    fun exists(): Boolean = accountExists(dir.path) && pinRecord.baseFile.exists()

    fun create(pin: ByteArray, displayName: String): Account {
        val created = createAccount(dir.path, pin, displayName)
        try {
            pinRecord.writeBytes(deviceKey.seal(created.pinRecord))
        } catch (e: Exception) {
            // Without its PIN record the new database could never be opened again.
            created.account.close()
            dir.listFiles()?.forEach { it.delete() }
            throw e
        }
        return created.account
    }

    /** @throws CoreException.WrongCredential and counts the failure. */
    fun unlockWithPin(pin: ByteArray): Account = withPinRecord { record -> coreUnlockWithPin(dir.path, record, pin) }

    /** Unlocks an account that was locked while running (sealed); like [unlockWithPin]. */
    fun unsealWithPin(account: Account, pin: ByteArray) {
        withPinRecord { record -> account.unsealWithPin(dir.path, record, pin) }
    }

    private fun <T> withPinRecord(unlock: (ByteArray) -> T): T {
        check(lockoutRemainingMs() == 0L) { "unlock attempted during lockout" }
        val record = deviceKey.open(pinRecord.readFully())
        try {
            return unlock(record).also { failedAttempts.delete() }
        } catch (e: CoreException.WrongCredential) {
            recordFailure()
            throw e
        }
    }

    /** Deletes the account and every key protecting it. Used when the PIN is forgotten. */
    fun reset() {
        dir.listFiles()?.forEach { it.delete() }
        deviceKey.delete()
        biometricKey.delete()
    }

    fun changePin(account: Account, newPin: ByteArray) {
        pinRecord.writeBytes(deviceKey.seal(account.changePin(newPin)))
    }

    // Biometric unlock.

    fun biometricEnabled(): Boolean = biometricSecret.baseFile.exists() && biometricRecord.baseFile.exists()

    /** A cipher to authenticate with `BiometricPrompt` before calling [enableBiometric]. */
    fun biometricEnrollCipher(): Cipher {
        biometricKey.delete()
        return biometricKey.encryptCipher()
    }

    fun enableBiometric(account: Account, authenticatedCipher: Cipher) {
        val unlock = account.createSecretUnlock()
        try {
            biometricRecord.writeBytes(deviceKey.seal(unlock.record))
            biometricSecret.writeBytes(KeystoreKey.sealWith(authenticatedCipher, unlock.secret))
        } finally {
            unlock.secret.fill(0)
        }
    }

    /**
     * A cipher to authenticate with `BiometricPrompt` before calling [unlockWithBiometric], or null if
     * biometric unlock is off or its key was invalidated (new biometric enrolled, screen lock removed);
     * in that case biometric unlock is turned off and the PIN still works.
     */
    fun biometricUnlockCipher(): Cipher? {
        if (!biometricEnabled()) return null
        return try {
            biometricKey.decryptCipher(biometricSecret.readFully())
        } catch (_: KeyPermanentlyInvalidatedException) {
            disableBiometric()
            null
        } catch (_: KeyLostException) {
            disableBiometric()
            null
        }
    }

    fun unlockWithBiometric(authenticatedCipher: Cipher): Account =
        withBiometricSecret(authenticatedCipher) { record, secret -> coreUnlockWithSecret(dir.path, record, secret) }

    /** Unlocks an account that was locked while running (sealed); like [unlockWithBiometric]. */
    fun unsealWithBiometric(account: Account, authenticatedCipher: Cipher) {
        withBiometricSecret(authenticatedCipher) { record, secret -> account.unsealWithSecret(dir.path, record, secret) }
    }

    private fun <T> withBiometricSecret(authenticatedCipher: Cipher, unlock: (ByteArray, ByteArray) -> T): T {
        val secret = KeystoreKey.openWith(authenticatedCipher, biometricSecret.readFully())
        try {
            val record = deviceKey.open(biometricRecord.readFully())
            return unlock(record, secret).also { failedAttempts.delete() }
        } finally {
            secret.fill(0)
        }
    }

    fun disableBiometric() {
        biometricSecret.delete()
        biometricRecord.delete()
        biometricKey.delete()
    }

    // Brute-force slowdown. This only hinders guessing through the UI; the real protection against
    // an attacker with the device is the hardware-bound key plus Argon2id.

    fun lockoutRemainingMs(now: Long = System.currentTimeMillis()): Long {
        val (count, lastFailureAt) = readFailures() ?: return 0
        if (count < FREE_ATTEMPTS) return 0
        val delay = min(BASE_DELAY_MS shl min(count - FREE_ATTEMPTS, 7), MAX_DELAY_MS)
        return (lastFailureAt + delay - now).coerceAtLeast(0)
    }

    private fun recordFailure() {
        val count = (readFailures()?.first ?: 0) + 1
        failedAttempts.writeBytes("$count ${System.currentTimeMillis()}".encodeToByteArray())
    }

    private fun readFailures(): Pair<Int, Long>? {
        if (!failedAttempts.baseFile.exists()) return null
        val parts = failedAttempts.readFully().decodeToString().split(' ')
        return parts.getOrNull(0)?.toIntOrNull()?.let { count -> count to (parts.getOrNull(1)?.toLongOrNull() ?: 0) }
    }

    private fun AtomicFile.writeBytes(bytes: ByteArray) {
        val out = startWrite()
        try {
            out.write(bytes)
            finishWrite(out)
        } catch (e: Exception) {
            failWrite(out)
            throw e
        }
    }

    private companion object {
        const val FREE_ATTEMPTS = 5
        const val BASE_DELAY_MS = 30_000L
        const val MAX_DELAY_MS = 60 * 60_000L
    }
}
