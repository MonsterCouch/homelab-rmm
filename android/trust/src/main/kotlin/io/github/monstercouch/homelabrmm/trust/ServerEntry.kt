package io.github.monstercouch.homelabrmm.trust

import java.net.URI

/**
 * How trust in a server is established.
 *
 * [PINNED] is the whole product: the SHA-256 of the leaf certificate DER,
 * supplied out of band and confirmed by a human, is the only thing that grants
 * trust - not the hostname, not the issuer, not the expiry, not the system CA
 * store, not TOFU.
 *
 * [SYSTEM] exists for the one documented fallback (`tailscale cert` on the
 * server, §9.6 / "Fallback if the A2 spike fails") and is marked in the UI as
 * the weaker mode. It is NOT a bypass: with an empty pin, a publicly-trusted
 * leaf raises no SSL error at all, so an [SslError][android.net.http.SslError]
 * arriving for a SYSTEM entry is a genuine failure and [TrustStore.evaluate]
 * rejects it. Fail-closed by construction, not by remembering a branch.
 */
enum class TrustMode {
    PINNED,
    SYSTEM;

    companion object {
        /** A non-empty, valid pin means PINNED; anything else means SYSTEM. */
        fun forPin(pinHex: String): TrustMode =
            if (Fingerprint.isValid(pinHex)) PINNED else SYSTEM
    }
}

/**
 * One server the phone knows about.
 *
 * The list of these is not secret (the console publishes the fingerprint). Its
 * *integrity* is the whole model: a silently mutated pin is a silently accepted
 * MITM. That is what `SealedCodec` plus the AndroidKeyStore key protects.
 */
data class ServerEntry(
    /** Stable opaque id; also the WebView profile name. */
    val id: String,
    /** Human label shown in the toolbar and the picker. */
    val label: String,
    /** Origin only: `https://host[:port]`, no path, no trailing slash. */
    val url: String,
    /** 64 lower-case hex characters, or "" for [TrustMode.SYSTEM]. */
    val pinHex: String,
    val trustMode: TrustMode,
    val addedAt: Long = 0L,
    val lastConnectedAt: Long = 0L,
    /** When the pin was last deliberately rotated through Trust review. */
    val pinRotatedAt: Long = 0L,
    // Deliberately NOT here: the last console path. It changes on every
    // onPageFinished, and rewriting the sealed trust blob dozens of times a
    // session would put the pins through a re-encrypt-and-write cycle for the
    // sake of a navigation convenience. It lives in store/Prefs.kt, unsealed,
    // keyed by server id - losing it costs one tap.
) {
    // URI.create, not URI(...): it wraps URISyntaxException in an
    // IllegalArgumentException, so a malformed stored url fails the same way as
    // every other malformed field rather than throwing a checked exception out
    // of a constructor.
    private val uri: URI = URI.create(url)

    /** Lower-case host. Pins are host-scoped: a redirect can never inherit one. */
    val host: String = uri.host?.lowercase().orEmpty()

    /** Explicit port, or 443 for https. */
    val port: Int = if (uri.port != -1) uri.port else 443

    /**
     * The origin in the spelling Chromium uses: the default port is omitted.
     * This is what `addWebMessageListener`'s allowedOriginRules and
     * `shouldOverrideUrlLoading` compare against.
     */
    val origin: String = if (port == 443) "https://$host" else "https://$host:$port"

    /** Absolute URL for a console path such as "/devices". */
    fun urlFor(path: String): String =
        origin + if (path.startsWith("/")) path else "/$path"

    init {
        require(host.isNotEmpty()) { "server entry has no host: $url" }
        require(uri.scheme?.equals("https", ignoreCase = true) == true) {
            "server entry is not https: $url"
        }
        require(trustMode != TrustMode.PINNED || Fingerprint.isValid(pinHex)) {
            "pinned server entry has no valid fingerprint"
        }
        require(trustMode != TrustMode.SYSTEM || pinHex.isEmpty()) {
            "system-trust server entry must carry no fingerprint"
        }
    }

    companion object {
        /**
         * Build an entry from user input, normalising the URL to an origin and
         * the fingerprint to canonical form. Throws [IllegalArgumentException]
         * on anything that is not an https origin, or on a fingerprint that is
         * neither empty nor 64 hex characters.
         */
        fun of(
            id: String,
            label: String,
            url: String,
            fingerprint: String,
            addedAt: Long = 0L,
            lastConnectedAt: Long = 0L,
            pinRotatedAt: Long = 0L,
        ): ServerEntry {
            val origin = normalizeOrigin(url)
            val fp = Fingerprint.normalize(fingerprint)
            require(fp.isEmpty() || Fingerprint.isValid(fp)) {
                "fingerprint must be 64 hex characters or empty, got ${fp.length}"
            }
            return ServerEntry(
                id = id,
                label = label,
                url = origin,
                pinHex = fp,
                trustMode = TrustMode.forPin(fp),
                addedAt = addedAt,
                lastConnectedAt = lastConnectedAt,
                pinRotatedAt = pinRotatedAt,
            )
        }

        /**
         * `https://Host:8443/whatever` -> `https://host:8443`.
         *
         * Rejects any non-https scheme (an `http://` entry is refused with a
         * reason: the release build sets `cleartextTrafficPermitted="false"`, so
         * storing one would produce a server that can never be loaded), and
         * rejects embedded credentials.
         */
        fun normalizeOrigin(raw: String): String {
            val trimmed = raw.trim()
            require(trimmed.isNotEmpty()) { "url is empty" }
            val u = try {
                URI.create(trimmed)
            } catch (e: Exception) {
                throw IllegalArgumentException("url is not a valid URI: $trimmed", e)
            }
            require(u.scheme != null && u.scheme.equals("https", ignoreCase = true)) {
                "url must start with https:// (got ${u.scheme ?: "no scheme"})"
            }
            require(u.userInfo == null) { "url must not contain credentials" }
            val h = u.host?.lowercase()
            require(!h.isNullOrEmpty()) { "url has no host" }
            return if (u.port == -1 || u.port == 443) "https://$h" else "https://$h:${u.port}"
        }
    }
}
