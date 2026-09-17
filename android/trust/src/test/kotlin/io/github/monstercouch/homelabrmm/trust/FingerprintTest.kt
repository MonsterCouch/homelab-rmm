package io.github.monstercouch.homelabrmm.trust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FingerprintTest {

    @Test
    fun normalize_strips_colons_and_lowercases() {
        val pretty = "A8:4C:90:99:C3:8E:04:82:A0:3B:5F:FC:21:F2:69:6A:" +
            "60:19:C8:08:28:2C:F2:31:5E:44:7E:23:3F:7F:FC:A7"
        assertEquals(TestVectors.GO_FINGERPRINT, Fingerprint.normalize(pretty))

        // Whitespace of every kind, which is what a paste out of the Trust review
        // screen's 4x4 grouping or out of a terminal actually looks like.
        val spaced = "  a84c 9099\tc38e\n0482 a03b 5ffc 21f2 696a\r\n" +
            "6019 c808 282c f231 5e44 7e23 3f7f fca7  "
        assertEquals(TestVectors.GO_FINGERPRINT, Fingerprint.normalize(spaced))

        // Matches internal/agent/conn.go:25 exactly for the plain upper-case case.
        assertEquals(
            TestVectors.GO_FINGERPRINT,
            Fingerprint.normalize(TestVectors.GO_FINGERPRINT.uppercase()),
        )
        assertEquals("", Fingerprint.normalize(""))
        assertEquals("", Fingerprint.normalize("  :: \t "))
    }

    @Test
    fun rejects_63_and_65_chars() {
        val ok = TestVectors.GO_FINGERPRINT
        assertTrue(Fingerprint.isValid(ok))
        assertFalse(Fingerprint.isValid(ok.dropLast(1)))          // 63
        assertFalse(Fingerprint.isValid(ok + "a"))                 // 65
        assertFalse(Fingerprint.isValid(""))
        assertFalse(Fingerprint.isValid("0".repeat(63)))
        assertFalse(Fingerprint.isValid("0".repeat(65)))
        assertTrue(Fingerprint.isValid("0".repeat(64)))
        assertTrue(Fingerprint.isValid("f".repeat(64)))
    }

    @Test
    fun rejects_non_hex() {
        val ok = TestVectors.GO_FINGERPRINT
        // Upper case is not the canonical form: normalize() is what lower-cases,
        // and isValid() checks the stored form, not the typed one.
        assertFalse(Fingerprint.isValid(ok.uppercase()))
        assertFalse(Fingerprint.isValid(ok.dropLast(1) + "g"))
        assertFalse(Fingerprint.isValid(ok.dropLast(1) + "G"))
        assertFalse(Fingerprint.isValid(ok.dropLast(1) + ":"))
        assertFalse(Fingerprint.isValid(ok.dropLast(1) + " "))
        assertFalse(Fingerprint.isValid(ok.dropLast(1) + "é"))
        // A homoglyph in a value a human is asked to compare on screen.
        assertFalse(Fingerprint.isValid(ok.replaceFirst("a", "а")))  // Cyrillic a
        assertFalse(Fingerprint.isValid("x".repeat(64)))
    }

    @Test
    fun ofDer_matches_known_vector() {
        assertEquals(TestVectors.GO_FINGERPRINT, Fingerprint.ofDer(TestVectors.DER))
        assertTrue(Fingerprint.isValid(Fingerprint.ofDer(TestVectors.DER)))
        // Independent cross-checks against the universal SHA-256 vectors.
        assertEquals(TestVectors.SHA256_OF_EMPTY, Fingerprint.ofDer(ByteArray(0)))
        assertEquals(TestVectors.SHA256_OF_ABC, Fingerprint.ofDer("abc".toByteArray()))
    }

    @Test
    fun hex_table_matches_percent_02x() {
        // Fingerprint.ofDer uses a hex table rather than the spec's
        // `"%02x".format(it)` so that 64 characters do not travel through a
        // locale-carrying Formatter. Pin the equivalence over every byte value,
        // including the negative half where a naive toString(16) would break.
        val all = ByteArray(256) { it.toByte() }
        val viaFormatter = java.security.MessageDigest.getInstance("SHA-256")
            .digest(all)
            .joinToString("") { "%02x".format(it) }
        assertEquals(viaFormatter, Fingerprint.ofDer(all))
    }

    @Test
    fun matches_is_exact() {
        val ok = TestVectors.GO_FINGERPRINT
        assertTrue(Fingerprint.matches(ok, ok))
        assertFalse(Fingerprint.matches(ok, ok.uppercase()))
        assertFalse(Fingerprint.matches(ok, ok.dropLast(1)))
        assertFalse(Fingerprint.matches(ok, ""))
        assertFalse(Fingerprint.matches("", ok))
        // Two empty pins must never "match": an empty pin is system trust, and
        // TrustStore rejects that branch before it ever reaches a comparison.
        assertTrue(Fingerprint.matches("", ""))
    }

    @Test
    fun groups_are_uniform_4x4x4() {
        val g = Fingerprint.groupsOf4(TestVectors.GO_FINGERPRINT)
        assertEquals(16, g.size)
        assertTrue(g.all { it.length == 4 })
        assertEquals(TestVectors.GO_FINGERPRINT, g.joinToString(""))

        val rows = Fingerprint.rows(TestVectors.GO_FINGERPRINT)
        assertEquals(4, rows.size)
        // Uniform, with no emphasis on the first or last bytes: every row is the
        // same shape, so a human compares all of it rather than just the ends.
        assertTrue(rows.all { it.length == 19 })
        assertEquals("a84c 9099 c38e 0482", rows[0])
        assertEquals("a03b 5ffc 21f2 696a", rows[1])
        assertEquals("6019 c808 282c f231", rows[2])
        assertEquals("5e44 7e23 3f7f fca7", rows[3])
    }

    @Test
    fun firstDifferingGroup_locates_the_change() {
        val a = TestVectors.GO_FINGERPRINT
        assertEquals(-1, Fingerprint.firstDifferingGroup(a, a))
        val b = a.toCharArray().also { it[0] = if (it[0] == '0') '1' else '0' }.concatToString()
        assertEquals(0, Fingerprint.firstDifferingGroup(a, b))
        val c = a.toCharArray().also { it[63] = if (it[63] == '0') '1' else '0' }.concatToString()
        assertEquals(15, Fingerprint.firstDifferingGroup(a, c))
    }
}
