package io.github.monstercouch.homelabrmm.trust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ServerListTest {

    private val entries = listOf(
        ServerEntry.of(
            id = "a",
            label = "Home \"lab\" \\ 1\nline",
            url = "https://rmm.tail-scale.ts.net:8443",
            fingerprint = TestVectors.GO_FINGERPRINT,
            addedAt = 1_700_000_000_000,
            lastConnectedAt = 1_700_000_100_000,
            pinRotatedAt = 1_700_000_200_000,
        ),
        ServerEntry.of(id = "b", label = "Public", url = "https://rmm.example.com", fingerprint = ""),
    )

    @Test
    fun encode_decode_round_trip() {
        val decoded = ServerList.decode(ServerList.encode(entries))
        assertEquals(entries, decoded)
        assertEquals(TrustMode.PINNED, decoded[0].trustMode)
        assertEquals(TrustMode.SYSTEM, decoded[1].trustMode)
        assertEquals(1_700_000_200_000, decoded[0].pinRotatedAt)
    }

    @Test
    fun empty_list_round_trips() {
        assertEquals(emptyList<ServerEntry>(), ServerList.decode(ServerList.encode(emptyList())))
    }

    @Test
    fun decode_refuses_a_trust_mode_that_disagrees_with_the_pin() {
        // The one downgrade that must never be expressible on disk: an entry
        // that claims SYSTEM while carrying a pin, or claims PINNED with none.
        val json = String(ServerList.encode(entries))
        val tampered = json.replace("\"trust\":\"PINNED\"", "\"trust\":\"SYSTEM\"")
        assertTrue(tampered != json)
        try {
            ServerList.decode(tampered.toByteArray())
            fail("a SYSTEM entry carrying a pin was accepted")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun decode_refuses_garbage() {
        for (bad in listOf("", "{", "[]", "null", "{\"v\":2,\"servers\":[]}", "{\"servers\":[]}", "not json")) {
            try {
                ServerList.decode(bad.toByteArray())
                fail("accepted: $bad")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
    }

    @Test
    fun decode_refuses_a_non_https_entry() {
        val json = String(ServerList.encode(entries)).replace("https://rmm.example.com", "http://rmm.example.com")
        try {
            ServerList.decode(json.toByteArray())
            fail("an http:// entry was accepted")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun export_text_carries_url_fingerprint_and_label() {
        val text = ServerList.exportText(entries)
        assertTrue(text.contains("https://rmm.tail-scale.ts.net:8443"))
        assertTrue(text.contains(TestVectors.GO_FINGERPRINT))
        assertTrue(text.contains("Public"))
        assertTrue(text.contains("system trust"))
        // Each entry round-trips back in through the pairing parser, so the
        // escape hatch is not a scavenger hunt through the console.
        for (line in text.lines().filter { it.startsWith("link:") }) {
            val uri = line.removePrefix("link:").trim()
            assertTrue("did not parse: $uri", PairUri.parse(uri) is PairParse.Ok)
        }
        assertTrue(ServerList.exportText(emptyList()).contains("(no servers)"))
    }

    @Test
    fun json_escapes_survive_a_round_trip() {
        val gnarly = "quote\" backslash\\ newline\n tab\t unicode é 中 control"
        val e = ServerEntry.of("id", gnarly, "https://rmm.example", TestVectors.GO_FINGERPRINT)
        val back = ServerList.decode(ServerList.encode(listOf(e)))
        assertEquals(gnarly, back.single().label)
        assertFalse(String(ServerList.encode(listOf(e))).contains(""))
    }
}
