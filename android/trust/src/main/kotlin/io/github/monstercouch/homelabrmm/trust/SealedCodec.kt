package io.github.monstercouch.homelabrmm.trust

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The blob layout for the sealed server list: `[12-byte IV][ciphertext || 16-byte tag]`.
 *
 * Framing only - the key comes from the caller. On Android that is the
 * AndroidKeyStore key under alias `rmm_trust_v1` (`store/Keystore.kt`); here in
 * plain JVM it can be any AES-256 key, which is what makes the tamper tests
 * runnable with no device.
 *
 * The server list is not secret (the console publishes the fingerprint). Its
 * INTEGRITY is the whole model: a silently mutated pin is a silently accepted
 * MITM. GCM's tag is what detects that, and [open] never has a fallback.
 */
object SealedCodec {

    /** GCM's standard nonce length, and the length AndroidKeyStore generates. */
    const val IV_BYTES = 12

    /** 128-bit tag - the JCE default for GCM and the AndroidKeyStore default. */
    const val TAG_BITS = 128
    const val TAG_BYTES = TAG_BITS / 8

    const val TRANSFORMATION = "AES/GCM/NoPadding"

    /**
     * Encrypt [plain] under [key], returning `iv || ciphertext || tag`.
     *
     * The IV is NOT supplied by the caller. It must not be: the AndroidKeyStore
     * key is generated with `setRandomizedEncryptionRequired(true)`, which makes
     * the provider reject a caller-chosen IV outright - and rightly so, because
     * an IV reused under the same GCM key is catastrophic.
     */
    fun seal(key: SecretKey, plain: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.ENCRYPT_MODE, key)
        val iv = c.iv
        check(iv.size == IV_BYTES) { "expected a $IV_BYTES-byte GCM IV, got ${iv.size}" }
        val ct = c.doFinal(plain)
        // A provider defaulting to a shorter tag would weaken integrity silently.
        check(ct.size == plain.size + TAG_BYTES) {
            "expected a $TAG_BYTES-byte GCM tag, got ${ct.size - plain.size}"
        }
        return iv + ct
    }

    /**
     * Decrypt a blob produced by [seal].
     *
     * Throws [AEADBadTagException] if the blob has been altered in any way -
     * including a truncated or structurally impossible blob, which is corruption
     * by another name and gets the same treatment. Callers must handle that one
     * exception by wiping the blob, wiping every WebView profile and forcing
     * re-pairing. There is deliberately no other failure mode to confuse it
     * with, no plaintext fallback, and no "use whatever bytes are there".
     */
    @Throws(AEADBadTagException::class)
    fun open(key: SecretKey, blob: ByteArray): ByteArray {
        if (blob.size < IV_BYTES + TAG_BYTES) {
            throw AEADBadTagException("sealed blob is ${blob.size} bytes, shorter than iv+tag")
        }
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 0, IV_BYTES))
        return c.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
    }
}
