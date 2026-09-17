package io.github.monstercouch.homelabrmm.trust

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class SealedCodecTest {

    private fun key(): SecretKey =
        KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private val plain = ServerList.encode(
        listOf(TestVectors.pinnedEntry(), TestVectors.systemEntry()),
    )

    @Test
    fun seal_and_open_round_trip() {
        val k = key()
        val blob = SealedCodec.seal(k, plain)
        assertEquals(SealedCodec.IV_BYTES + plain.size + SealedCodec.TAG_BYTES, blob.size)
        assertArrayEquals(plain, SealedCodec.open(k, blob))
    }

    @Test
    fun seal_never_repeats_an_iv() {
        // The IV comes from the provider, never from the caller: the
        // AndroidKeyStore key is generated with setRandomizedEncryptionRequired(true),
        // and an IV reused under one GCM key is catastrophic.
        val k = key()
        val ivs = (1..64).map { SealedCodec.seal(k, plain).copyOf(SealedCodec.IV_BYTES).toList() }
        assertEquals(64, ivs.toSet().size)
    }

    @Test
    fun sealed_blob_rejects_tag_mutation() {
        val k = key()
        val blob = SealedCodec.seal(k, plain)
        for (i in blob.size - SealedCodec.TAG_BYTES until blob.size) {
            val bad = blob.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            expectBadTag(k, bad, "tag byte $i")
        }
    }

    @Test
    fun sealed_blob_rejects_iv_mutation() {
        val k = key()
        val blob = SealedCodec.seal(k, plain)
        for (i in 0 until SealedCodec.IV_BYTES) {
            val bad = blob.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            expectBadTag(k, bad, "iv byte $i")
        }
    }

    @Test
    fun sealed_blob_rejects_ciphertext_mutation() {
        // This is the one that matters in practice: a flipped bit inside the
        // ciphertext is a silently mutated pin, which is a silently accepted MITM.
        val k = key()
        val blob = SealedCodec.seal(k, plain)
        val ctStart = SealedCodec.IV_BYTES
        val ctEnd = blob.size - SealedCodec.TAG_BYTES
        for (i in intArrayOf(ctStart, ctStart + 1, (ctStart + ctEnd) / 2, ctEnd - 1)) {
            val bad = blob.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            expectBadTag(k, bad, "ciphertext byte $i")
        }
    }

    @Test
    fun sealed_blob_rejects_truncation_and_garbage() {
        val k = key()
        val blob = SealedCodec.seal(k, plain)
        expectBadTag(k, blob.copyOf(blob.size - 1), "truncated by one byte")
        expectBadTag(k, ByteArray(0), "empty blob")
        expectBadTag(k, ByteArray(SealedCodec.IV_BYTES), "iv only")
        expectBadTag(k, ByteArray(SealedCodec.IV_BYTES + SealedCodec.TAG_BYTES - 1), "shorter than iv+tag")
        expectBadTag(k, ByteArray(128) { 0x41 }, "arbitrary bytes")
    }

    @Test
    fun sealed_blob_rejects_a_different_key() {
        // An uninstall or a signing-identity change destroys the AndroidKeyStore
        // key. The blob left behind must not open under a fresh one.
        val blob = SealedCodec.seal(key(), plain)
        expectBadTag(key(), blob, "a different key")
    }

    @Test
    fun opening_never_falls_back_to_plaintext() {
        // A caller that catches AEADBadTagException and reads the bytes anyway is
        // the failure this whole design exists to prevent. Prove that the bytes
        // never come back: every mutation path throws, none returns a value.
        val k = key()
        val blob = SealedCodec.seal(k, plain)
        var returned = false
        for (i in blob.indices) {
            val bad = blob.copyOf().also { it[i] = (it[i].toInt() xor 0x80).toByte() }
            try {
                SealedCodec.open(k, bad)
                returned = true
            } catch (e: AEADBadTagException) {
                // expected
            }
        }
        assertFalse("a mutated blob opened successfully", returned)
    }

    @Test
    fun the_blob_is_iv_then_ciphertext_and_tag() {
        val k = key()
        val small = byteArrayOf(1, 2, 3)
        val blob = SealedCodec.seal(k, small)
        assertEquals(SealedCodec.IV_BYTES + 3 + SealedCodec.TAG_BYTES, blob.size)
        assertEquals(12, SealedCodec.IV_BYTES)
        assertEquals(16, SealedCodec.TAG_BYTES)
        assertEquals(128, SealedCodec.TAG_BITS)
        assertArrayEquals(small, SealedCodec.open(k, blob))
        // The plaintext is not sitting in the blob in the clear.
        assertTrue(blob.drop(SealedCodec.IV_BYTES).take(3).toByteArray().toList() != small.toList())
    }

    private fun expectBadTag(k: SecretKey, blob: ByteArray, what: String) {
        try {
            SealedCodec.open(k, blob)
            fail("$what was accepted")
        } catch (e: AEADBadTagException) {
            // expected: the one failure mode callers must handle by wiping and re-pairing
        }
    }
}
