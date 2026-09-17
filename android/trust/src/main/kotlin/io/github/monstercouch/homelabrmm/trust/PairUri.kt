package io.github.monstercouch.homelabrmm.trust

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets.UTF_8

/** What a `homelabrmm://pair` URI carries. Nothing here is trusted yet. */
data class PairRequest(
    /** Normalised https origin. */
    val url: String,
    /** 64 lower-case hex characters, or "" meaning system trust. */
    val fingerprint: String,
    /** Optional human label; may be empty. */
    val label: String,
    val source: Source,
) {
    enum class Source { MANUAL, QR, DEEP_LINK }
}

/** Parse outcome. [Err.reason] is shown to the operator verbatim. */
sealed interface PairParse {
    data class Ok(val request: PairRequest) : PairParse
    data class Err(val reason: String) : PairParse
}

/**
 * `homelabrmm://pair?url=<enc>&fp=<64hex>&name=<label>` - the one string that
 * the console's QR code, the copyable text beside it, and a deep link from a
 * note or a password manager all carry.
 *
 * Parsed with [java.net.URI], never `android.net.Uri`: this module is plain JVM
 * so that `./gradlew :trust:test` needs no device, and `android.net.Uri.parse`
 * throws "not mocked" under a stub android.jar.
 *
 * Parsing does NOT establish trust. All three pairing channels converge on the
 * Trust review screen, where a human confirms the fingerprint and a pinned
 * probe must succeed before anything is stored. A deep link never auto-adds and
 * never auto-navigates.
 */
object PairUri {

    const val SCHEME = "homelabrmm"
    const val HOST = "pair"

    /** Render the URI the console puts in its QR code and its copyable text. */
    fun build(url: String, fingerprint: String, label: String): String {
        val q = buildString {
            append("url=").append(enc(url))
            append("&fp=").append(enc(Fingerprint.normalize(fingerprint)))
            if (label.isNotEmpty()) append("&name=").append(enc(label))
        }
        return "$SCHEME://$HOST?$q"
    }

    fun parse(raw: String, source: PairRequest.Source = PairRequest.Source.DEEP_LINK): PairParse {
        val text = raw.trim()
        if (text.isEmpty()) return PairParse.Err("empty pairing link")

        val uri = try {
            URI(text)
        } catch (e: Exception) {
            return PairParse.Err("not a valid pairing link")
        }

        if (!SCHEME.equals(uri.scheme, ignoreCase = true)) {
            return PairParse.Err("not a $SCHEME:// link")
        }
        // URI("homelabrmm://pair?...").host == "pair". An authority that is not
        // exactly `pair` is some other, unknown verb: refuse it rather than guess.
        if (!HOST.equals(uri.host, ignoreCase = true)) {
            return PairParse.Err("unknown $SCHEME action: ${uri.authority ?: "(none)"}")
        }

        val q = query(uri.rawQuery)

        val rawUrl = q["url"]?.trim().orEmpty()
        if (rawUrl.isEmpty()) return PairParse.Err("pairing link carries no server URL")
        val origin = try {
            ServerEntry.normalizeOrigin(rawUrl)
        } catch (e: IllegalArgumentException) {
            return PairParse.Err(e.message ?: "server URL is not usable")
        }

        val fp = Fingerprint.normalize(q["fp"].orEmpty())
        if (fp.isNotEmpty() && !Fingerprint.isValid(fp)) {
            return PairParse.Err(
                "fingerprint must be ${Fingerprint.HEX_LENGTH} hex characters, got ${fp.length}"
            )
        }

        val label = q["name"].orEmpty().trim()
        return PairParse.Ok(PairRequest(url = origin, fingerprint = fp, label = label, source = source))
    }

    private fun enc(s: String): String = URLEncoder.encode(s, UTF_8).replace("+", "%20")

    private fun query(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (part in rawQuery.split('&')) {
            if (part.isEmpty()) continue
            val i = part.indexOf('=')
            val k = if (i < 0) part else part.substring(0, i)
            val v = if (i < 0) "" else part.substring(i + 1)
            val key = dec(k)
            // First wins: a duplicated ?fp= must not be able to override the
            // value a human is about to be shown.
            if (!out.containsKey(key)) out[key] = dec(v)
        }
        return out
    }

    private fun dec(s: String): String = try {
        URLDecoder.decode(s, UTF_8)
    } catch (e: Exception) {
        s
    }
}
