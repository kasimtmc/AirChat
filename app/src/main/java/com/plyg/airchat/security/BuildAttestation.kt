package com.plyg.airchat.security

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.plyg.airchat.BuildConfig
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * This phone's key attestation (rust/airchat-protocol/docs/protocol.md §6.10): a P-256 key in the secure hardware,
 * attested with a challenge bound to the AirChat account, which then signs each link so contacts
 * can see the build is the official one on a verified phone. The key never leaves the hardware;
 * the certificate chain says nothing secret.
 */
object BuildAttestation {
    private const val PREFIX = "airchat_attest_"
    private const val TAG = "AirChat"

    /**
     * The chain of the attested key for [challenge], the key's certificate first, without the
     * root; made once per account. Null where the phone cannot attest (no secure hardware, or no
     * attestation keys provisioned yet, as can happen offline).
     */
    fun chain(challenge: ByteArray): List<ByteArray>? = try {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = alias(challenge)
        // One key per account: those of earlier accounts go.
        store.aliases().toList().filter { it.startsWith(PREFIX) && it != alias }.forEach(store::deleteEntry)
        if (!store.containsAlias(alias)) {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(
                    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                        .build(),
                )
                generateKeyPair()
            }
        }
        val certificates = store.getCertificateChain(alias)?.map { it as X509Certificate }.orEmpty()
        // The root is known to everyone; leaving it out keeps the record small.
        certificates.filterNot { it.subjectX500Principal == it.issuerX500Principal }.map { it.encoded }
            .takeIf { it.isNotEmpty() }
    } catch (e: Exception) {
        if (BuildConfig.DEBUG) Log.w(TAG, "no key attestation", e)
        null
    }

    /** The attested key's signature (SHA256withECDSA, DER) over [message]; null without the key. */
    fun sign(challenge: ByteArray, message: ByteArray): ByteArray? = try {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = store.getKey(alias(challenge), null) as? PrivateKey
        key?.let { Signature.getInstance("SHA256withECDSA").apply { initSign(it); update(message) }.sign() }
    } catch (e: Exception) {
        if (BuildConfig.DEBUG) Log.w(TAG, "could not sign the attestation proof", e)
        null
    }

    /** SHA-256 of the certificate this app is signed with, for debug builds to trust their own. */
    fun ownSigner(context: Context): ByteArray? = try {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            ?.let { MessageDigest.getInstance("SHA-256").digest(it) }
    } catch (e: Exception) {
        null
    }

    private fun alias(challenge: ByteArray) = PREFIX + challenge.copyOf(8).joinToString("") { "%02x".format(it) }
}
