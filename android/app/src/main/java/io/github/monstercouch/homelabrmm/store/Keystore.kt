package io.github.monstercouch.homelabrmm.store

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * The AES-256-GCM key, held in AndroidKeyStore, that seals the server list.
 *
 * The list is not secret - the console publishes the fingerprint on its
 * Settings page. Its INTEGRITY is the whole model: a silently mutated pin is a
 * silently accepted MITM. The key exists so that a tampered blob fails a GCM
 * tag check instead of quietly becoming a different set of pins.
 *
 * `androidx.security:security-crypto` is deliberately not used: every API in it
 * was deprecated in its first and final stable release "in favour of existing
 * platform APIs and direct use of Android Keystore", and its POM drags in
 * tink-android. This is that direct use.
 */
object Keystore {

    /**
     * Versioned so that a future key-policy change can be a new alias plus a
     * migration, rather than a silent reinterpretation of existing blobs.
     */
    const val ALIAS = "rmm_trust_v1"

    private const val PROVIDER = "AndroidKeyStore"

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    fun exists(): Boolean = runCatching { keyStore().containsAlias(ALIAS) }.getOrDefault(false)

    /**
     * Fetch the sealing key, generating it on first use.
     *
     * Two properties are deliberately NOT set, and both matter:
     *
     * - `setUserAuthenticationRequired` - the server picker must render before
     *   the biometric prompt runs. Binding the key to user auth would mean the
     *   list cannot be read to draw the screen that offers to unlock it.
     *
     * - `setUnlockedDeviceRequired` - it silently breaks the moment the v1.1
     *   alert poller needs to read the server list while the device is locked.
     *   If it is ever wanted, split into an unlocked-device-required key for
     *   pins and a plain key for what a worker needs; do not bolt it onto this
     *   alias.
     *
     * `setRandomizedEncryptionRequired(true)` is what makes a caller-supplied IV
     * impossible, which is why [io.github.monstercouch.homelabrmm.trust.SealedCodec]
     * never passes one.
     */
    fun getOrCreate(): SecretKey {
        val ks = keyStore()
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return kg.generateKey()
    }

    /**
     * Destroy the key. Every existing blob becomes permanently unopenable, so
     * this is only ever called as part of the wipe-and-re-pair path in
     * [ServerStore] - never as a way to "recover" from a read failure.
     */
    fun delete() {
        runCatching { keyStore().deleteEntry(ALIAS) }
    }
}
