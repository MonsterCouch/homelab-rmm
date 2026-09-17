package io.github.monstercouch.homelabrmm.trust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class TrustStoreTest {

    private val entry = TestVectors.pinnedEntry()
    private val store = TrustStore.of(entry)
    private val url = "https://${entry.host}:${entry.port}/devices"

    @Test
    fun evaluate_accepts_exact_match() {
        assertEquals(
            Decision.Trusted,
            store.evaluate(url, TestVectors.DER, entry.host),
        )
        // Host casing must not matter - Chromium can hand back either.
        assertEquals(
            Decision.Trusted,
            store.evaluate(url, TestVectors.DER, entry.host.uppercase()),
        )
    }

    @Test
    fun evaluate_rejects_unknown_host() {
        // A redirect can never inherit a pin.
        val d = store.evaluate("https://evil.example/", TestVectors.DER, "evil.example")
        assertEquals(Decision.Rejected(Failure.UnknownHost("evil.example")), d)

        // Not even a subdomain of a pinned host.
        val sub = store.evaluate(
            "https://a.${entry.host}/",
            TestVectors.DER,
            "a.${entry.host}",
        )
        assertEquals(Decision.Rejected(Failure.UnknownHost("a.${entry.host}")), sub)

        // An empty store trusts nothing at all.
        assertTrue(TrustStore.EMPTY.evaluate(url, TestVectors.DER, entry.host) is Decision.Rejected)
    }

    @Test
    fun evaluate_rejects_no_host() {
        assertEquals(Decision.Rejected(Failure.NoHost(url)), store.evaluate(url, TestVectors.DER, null))
        assertEquals(Decision.Rejected(Failure.NoHost(url)), store.evaluate(url, TestVectors.DER, ""))
        assertEquals(Decision.Rejected(Failure.NoHost("")), store.evaluate(null, TestVectors.DER, null))
    }

    @Test
    fun evaluate_rejects_null_der() {
        // The platform handing back no leaf is not a reason to trust anything.
        assertEquals(
            Decision.Rejected(Failure.NoCertificate),
            store.evaluate(url, null, entry.host),
        )
        // Nor is an empty one - it hashes to a perfectly valid, wrong digest.
        val d = store.evaluate(url, ByteArray(0), entry.host)
        assertTrue(d is Decision.Rejected && d.why is Failure.PinMismatch)
    }

    @Test
    fun evaluate_rejects_system_trust_mode() {
        // An empty pin means system trust. A publicly-trusted leaf raises no SSL
        // error at all, so reaching the handler for such an entry is a genuine
        // failure. Fail-closed by construction, not by remembering a branch.
        val sys = TestVectors.systemEntry()
        val s = TrustStore.of(sys)
        assertEquals(
            Decision.Rejected(Failure.UnknownHost(sys.host)),
            s.evaluate("https://${sys.host}/", TestVectors.DER, sys.host),
        )
        // Even when the DER is the very certificate that would have matched a pin.
        assertEquals(
            Decision.Rejected(Failure.UnknownHost(sys.host)),
            s.evaluate("https://${sys.host}/", TestVectors.DER, sys.host.uppercase()),
        )
    }

    @Test
    fun evaluate_rejects_every_single_char_mutation() {
        val real = TestVectors.GO_FINGERPRINT
        val hex = "0123456789abcdef"
        var checked = 0
        for (i in 0 until Fingerprint.HEX_LENGTH) {
            for (c in hex) {
                if (c == real[i]) continue
                val mutated = real.toCharArray().also { it[i] = c }.concatToString()
                val s = TrustStore.of(TestVectors.pinnedEntry(fp = mutated))
                when (val d = s.evaluate(url, TestVectors.DER, entry.host)) {
                    is Decision.Trusted ->
                        fail("pin differing at index $i ('${real[i]}' -> '$c') was accepted")
                    is Decision.Rejected -> {
                        val why = d.why
                        assertTrue("expected PinMismatch at $i", why is Failure.PinMismatch)
                        why as Failure.PinMismatch
                        assertEquals(real, why.presented)
                        assertEquals(mutated, why.expected)
                    }
                }
                checked++
            }
        }
        // 64 positions x 15 substitutions.
        assertEquals(64 * 15, checked)
    }

    @Test
    fun evaluate_rejects_a_mutated_certificate() {
        // The other direction: the stored pin is right, the presented DER is not.
        for (i in intArrayOf(0, 1, 100, TestVectors.DER.size / 2, TestVectors.DER.size - 1)) {
            val der = TestVectors.DER.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            val d = store.evaluate(url, der, entry.host)
            assertTrue("mutating DER byte $i was accepted", d is Decision.Rejected)
            d as Decision.Rejected
            val why = d.why as Failure.PinMismatch
            assertEquals(entry.pinHex, why.expected)
            assertEquals(Fingerprint.ofDer(der), why.presented)
        }
        // A truncated chain is a mismatch, never a pass.
        assertTrue(
            store.evaluate(url, TestVectors.DER.copyOf(TestVectors.DER.size - 1), entry.host)
                is Decision.Rejected,
        )
    }

    @Test
    fun evaluate_is_a_pure_function_of_its_inputs() {
        // The SslErrorHandler callback is not once-per-session: it re-fires after
        // every process start and can re-fire per host, so the handler must be
        // idempotent and side-effect free.
        val first = store.evaluate(url, TestVectors.DER, entry.host)
        repeat(5) { assertEquals(first, store.evaluate(url, TestVectors.DER, entry.host)) }
        val bad = TrustStore.of(TestVectors.pinnedEntry(fp = "0".repeat(64)))
        val r1 = bad.evaluate(url, TestVectors.DER, entry.host)
        repeat(5) { assertEquals(r1, bad.evaluate(url, TestVectors.DER, entry.host)) }
    }

    @Test
    fun the_url_never_influences_the_lookup() {
        // The pin is found by host alone. The rest of the URL is only carried
        // into the NoHost failure for the error message.
        for (u in listOf(
            "https://${entry.host}:${entry.port}/",
            "https://${entry.host}:${entry.port}/devices/abc/terminal",
            "wss://${entry.host}:${entry.port}/ws/shell/abc",
            "https://${entry.host}:1/anything?x=1#y",
        )) {
            assertEquals(Decision.Trusted, store.evaluate(u, TestVectors.DER, entry.host))
        }
    }

    @Test
    fun entry_requires_https_and_a_host() {
        assertThrows { ServerEntry.normalizeOrigin("http://rmm.example:8443") }
        assertThrows { ServerEntry.normalizeOrigin("ftp://rmm.example") }
        assertThrows { ServerEntry.normalizeOrigin("rmm.example:8443") }
        assertThrows { ServerEntry.normalizeOrigin("https:///devices") }
        assertThrows { ServerEntry.normalizeOrigin("https://user:pw@rmm.example") }
        assertThrows { ServerEntry.normalizeOrigin("") }
        assertEquals("https://rmm.example:8443", ServerEntry.normalizeOrigin("HTTPS://RMM.Example:8443/x?y#z"))
        assertEquals("https://rmm.example", ServerEntry.normalizeOrigin("https://rmm.example:443/"))
        assertEquals("https://rmm.example", ServerEntry.normalizeOrigin(" https://rmm.example "))
    }

    @Test
    fun entry_derives_host_port_and_origin() {
        val e = ServerEntry.of("id", "Home", "https://Rmm.Example:8443/ignored", TestVectors.GO_FINGERPRINT)
        assertEquals("rmm.example", e.host)
        assertEquals(8443, e.port)
        assertEquals("https://rmm.example:8443", e.origin)
        assertEquals("https://rmm.example:8443/devices", e.urlFor("/devices"))
        assertEquals("https://rmm.example:8443/devices", e.urlFor("devices"))
        assertEquals(TrustMode.PINNED, e.trustMode)

        val d = ServerEntry.of("id", "Home", "https://rmm.example", "")
        assertEquals(443, d.port)
        assertEquals("https://rmm.example", d.origin)
        assertEquals(TrustMode.SYSTEM, d.trustMode)

        // A fingerprint that is neither empty nor 64 hex characters is refused
        // here rather than quietly downgraded to system trust.
        assertThrows { ServerEntry.of("id", "Home", "https://rmm.example", "abc") }
        assertThrows { ServerEntry.of("id", "Home", "https://rmm.example", "0".repeat(63)) }
    }

    @Test
    fun a_pinned_entry_cannot_be_built_without_a_valid_pin() {
        assertThrows {
            ServerEntry("x", "l", "https://h", "", TrustMode.PINNED)
        }
        assertThrows {
            ServerEntry("x", "l", "https://h", TestVectors.GO_FINGERPRINT, TrustMode.SYSTEM)
        }
        assertThrows {
            ServerEntry("x", "l", "http://h", TestVectors.GO_FINGERPRINT, TrustMode.PINNED)
        }
    }

    private fun assertThrows(body: () -> Unit) {
        try {
            body()
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }
}
