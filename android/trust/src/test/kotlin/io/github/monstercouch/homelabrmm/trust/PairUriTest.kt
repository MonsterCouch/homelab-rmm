package io.github.monstercouch.homelabrmm.trust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PairUriTest {

    private fun err(raw: String): PairParse.Err {
        val p = PairUri.parse(raw)
        assertTrue("expected $raw to be rejected, got $p", p is PairParse.Err)
        return p as PairParse.Err
    }

    private fun ok(raw: String): PairRequest {
        val p = PairUri.parse(raw)
        assertTrue("expected $raw to parse, got $p", p is PairParse.Ok)
        return (p as PairParse.Ok).request
    }

    @Test
    fun pair_uri_rejects_http() {
        // An http:// entry could never be loaded anyway: the release build sets
        // cleartextTrafficPermitted="false". Refuse it here, with a reason.
        val e = err("homelabrmm://pair?url=http%3A%2F%2Frmm.example%3A8443&fp=${TestVectors.GO_FINGERPRINT}")
        assertTrue(e.reason, e.reason.contains("https"))
        err("homelabrmm://pair?url=ftp%3A%2F%2Frmm.example&fp=${TestVectors.GO_FINGERPRINT}")
        err("homelabrmm://pair?url=javascript%3Aalert(1)&fp=${TestVectors.GO_FINGERPRINT}")
        err("homelabrmm://pair?url=rmm.example%3A8443&fp=${TestVectors.GO_FINGERPRINT}")
    }

    @Test
    fun pair_uri_rejects_short_fp() {
        val short = TestVectors.GO_FINGERPRINT.dropLast(1)
        val e = err("homelabrmm://pair?url=https%3A%2F%2Frmm.example%3A8443&fp=$short")
        assertTrue(e.reason, e.reason.contains("63"))
        err("homelabrmm://pair?url=https%3A%2F%2Frmm.example%3A8443&fp=${TestVectors.GO_FINGERPRINT}a")
        err("homelabrmm://pair?url=https%3A%2F%2Frmm.example%3A8443&fp=${TestVectors.GO_FINGERPRINT.dropLast(1)}g")
    }

    @Test
    fun pair_uri_rejects_empty_host() {
        val e = err("homelabrmm://pair?url=https%3A%2F%2F%2Fdevices&fp=${TestVectors.GO_FINGERPRINT}")
        assertTrue(e.reason, e.reason.contains("host") || e.reason.contains("URI"))
        err("homelabrmm://pair?url=https%3A%2F%2F&fp=${TestVectors.GO_FINGERPRINT}")
        err("homelabrmm://pair?fp=${TestVectors.GO_FINGERPRINT}")
        err("homelabrmm://pair?url=&fp=${TestVectors.GO_FINGERPRINT}")
    }

    @Test
    fun pair_uri_rejects_the_wrong_scheme_or_action() {
        err("https://rmm.example/pair?url=https%3A%2F%2Frmm.example")
        err("homelabrmm://enroll?url=https%3A%2F%2Frmm.example")
        err("homelabrmm://pair.evil.example?url=https%3A%2F%2Frmm.example")
        err("")
        err("   ")
        err("not a uri at all")
    }

    @Test
    fun pair_uri_accepts_an_empty_fingerprint_as_system_trust() {
        // An empty fingerprint is legal and means system trust - the documented
        // `tailscale cert` fallback. It is still shown in Trust review, marked
        // as the weaker mode.
        val r = ok("homelabrmm://pair?url=https%3A%2F%2Frmm.example%3A8443&name=Home")
        assertEquals("https://rmm.example:8443", r.url)
        assertEquals("", r.fingerprint)
        assertEquals("Home", r.label)
    }

    @Test
    fun pair_uri_round_trips_and_normalises() {
        val built = PairUri.build(
            "https://RMM.Example:8443",
            "A8:4C:90:99:C3:8E:04:82:A0:3B:5F:FC:21:F2:69:6A:" +
                "60:19:C8:08:28:2C:F2:31:5E:44:7E:23:3F:7F:FC:A7",
            "Home lab & co",
        )
        val r = ok(built)
        assertEquals("https://rmm.example:8443", r.url)
        assertEquals(TestVectors.GO_FINGERPRINT, r.fingerprint)
        assertEquals("Home lab & co", r.label)
        assertEquals(PairRequest.Source.DEEP_LINK, r.source)

        // The source badge is carried, never inferred.
        val scanned = PairUri.parse(built, PairRequest.Source.QR)
        assertEquals(PairRequest.Source.QR, (scanned as PairParse.Ok).request.source)
    }

    @Test
    fun pair_uri_first_fp_wins() {
        // A duplicated parameter must not be able to override the value a human
        // is about to be shown on the Trust review screen.
        val real = TestVectors.GO_FINGERPRINT
        val other = "0".repeat(64)
        val r = ok("homelabrmm://pair?url=https%3A%2F%2Frmm.example&fp=$real&fp=$other")
        assertEquals(real, r.fingerprint)
    }

    @Test
    fun pair_uri_drops_path_and_credentials() {
        val r = ok("homelabrmm://pair?url=https%3A%2F%2Frmm.example%3A8443%2Fdevices%3Fq%3D1&fp=${TestVectors.GO_FINGERPRINT}")
        assertEquals("https://rmm.example:8443", r.url)
        err("homelabrmm://pair?url=https%3A%2F%2Fu%3Ap%40rmm.example&fp=${TestVectors.GO_FINGERPRINT}")
    }

    @Test
    fun pair_uri_tolerates_pasted_whitespace_in_the_fingerprint() {
        val spaced = Fingerprint.rows(TestVectors.GO_FINGERPRINT).joinToString(" ")
        val enc = java.net.URLEncoder.encode(spaced, Charsets.UTF_8).replace("+", "%20")
        val r = ok("homelabrmm://pair?url=https%3A%2F%2Frmm.example&fp=$enc")
        assertEquals(TestVectors.GO_FINGERPRINT, r.fingerprint)
    }
}
