package io.github.monstercouch.homelabrmm.trust

import java.nio.charset.StandardCharsets.US_ASCII
import java.security.MessageDigest

/**
 * The SHA-256 fingerprint of a server's leaf certificate DER, in the one
 * canonical spelling the whole system uses: lower-case hex, 64 characters, no
 * colons.
 *
 * That spelling is not a choice made here. It is byte-identical to:
 *   - `Fingerprint()` at internal/server/tls.go:45-49, `hex(sha256(der))`,
 *     which is what the console prints on its Settings page;
 *   - what every agent compares at internal/agent/conn.go:36, after the same
 *     `strings.ToLower(strings.ReplaceAll(fp, ":", ""))` normalisation at :25;
 *   - the bytes Chromium hands Java in `onReceivedSslError`, which
 *     aw_contents_client_bridge.cc:143 takes from `cert->cert_buffer()`.
 *
 * So the 64-character string the console prints, the string every agent pins,
 * and the string the phone stores are literally the same string.
 */
object Fingerprint {

    /** A fingerprint is exactly 64 lower-case hex characters. */
    const val HEX_LENGTH = 64

    private val HEX_DIGITS = "0123456789abcdef".toCharArray()

    /**
     * Paste-friendly normalisation. Matches internal/agent/conn.go:25 exactly,
     * plus whitespace stripping so a fingerprint copied out of a terminal or
     * read off a screen in 4x4 groups pastes cleanly.
     *
     * [String.lowercase] with no argument is locale-independent; the
     * locale-sensitive `toLowerCase()` would mangle this under a Turkish locale.
     */
    fun normalize(s: String): String =
        s.replace(":", "").filterNot(Char::isWhitespace).lowercase()

    /** True only for the canonical form: 64 characters, all of `[0-9a-f]`. */
    fun isValid(s: String): Boolean =
        s.length == HEX_LENGTH && s.all { it in '0'..'9' || it in 'a'..'f' }

    /**
     * hex(sha256(der)), lower case, no colons - matching internal/server/tls.go:45-49.
     *
     * Equivalent to `digest.joinToString("") { "%02x".format(it) }` but without
     * routing 64 characters through a locale-carrying `java.util.Formatter`.
     * `hex_table_matches_percent_02x` in the test suite pins the equivalence
     * across all 256 byte values.
     */
    fun ofDer(der: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(der)
        val out = CharArray(digest.size * 2)
        for (i in digest.indices) {
            val b = digest[i].toInt() and 0xff
            out[i * 2] = HEX_DIGITS[b ushr 4]
            out[i * 2 + 1] = HEX_DIGITS[b and 0x0f]
        }
        return String(out)
    }

    /**
     * Length-independent comparison of two already-normalised fingerprints.
     *
     * The secrecy of a published fingerprint is not the point - the console
     * prints it. Using [MessageDigest.isEqual] costs nothing and removes the
     * class of question entirely.
     */
    fun matches(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(US_ASCII), b.toByteArray(US_ASCII))

    /** 16 groups of 4 characters, for display. */
    fun groupsOf4(fp: String): List<String> = fp.chunked(4)

    /**
     * 4 rows of 4 groups of 4 characters, for the Trust review screen.
     *
     * Uniform, with NO emphasis on the first or last bytes: emphasising the ends
     * invites exactly the partial comparison a prefix-collision attack targets.
     */
    fun rows(fp: String): List<String> =
        groupsOf4(fp).chunked(4).map { it.joinToString(" ") }

    /**
     * Index of the first 4-character group in which [a] and [b] differ, or -1
     * when they are equal. Used only by the pin-mismatch screen, on two values
     * that have already been rejected.
     */
    fun firstDifferingGroup(a: String, b: String): Int {
        val ga = groupsOf4(a)
        val gb = groupsOf4(b)
        val n = minOf(ga.size, gb.size)
        for (i in 0 until n) if (ga[i] != gb[i]) return i
        return if (ga.size == gb.size) -1 else n
    }
}
