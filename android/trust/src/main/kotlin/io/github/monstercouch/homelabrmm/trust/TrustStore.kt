package io.github.monstercouch.homelabrmm.trust

/** The outcome of one certificate evaluation. There is no third state. */
sealed interface Decision {
    data object Trusted : Decision
    data class Rejected(val why: Failure) : Decision
}

/** Why a certificate was rejected. Every branch is a dead end in the UI. */
sealed interface Failure {
    /** The URL had no parseable host, so no pin could be looked up. */
    data class NoHost(val url: String) : Failure

    /**
     * Nothing is stored for this host. Covers a redirect to somewhere else - a
     * redirect can never inherit a pin - and a SYSTEM-trust entry, for which an
     * SSL error is by definition a genuine failure.
     */
    data class UnknownHost(val host: String) : Failure

    /** The platform handed us no leaf certificate. Never proceed on this. */
    data object NoCertificate : Failure

    /** The leaf hashed to something other than the stored pin. */
    data class PinMismatch(
        val host: String,
        val presented: String,
        val expected: String,
    ) : Failure
}

/**
 * The single source of pin truth.
 *
 * Both call sites use this one object: `RmmWebViewClient.onReceivedSslError`
 * (which secures navigation, subresources, `fetch`, `EventSource` and `wss://`
 * alike, because `AwContentBrowserClient::AllowCertificateError` ignores
 * `is_primary_main_frame_request`) and `PinnedHttp`'s `X509TrustManager`. Two
 * copies is exactly how two copies drift.
 *
 * [evaluate] is an idempotent, side-effect-free pure function of
 * (URL host, stored pin, leaf DER). It has to be: the `SslErrorHandler`
 * callback is not once-per-session. `AwSslHostStateDelegate` keeps allow
 * decisions in an in-memory map that dies with the process, and
 * `CertPolicy::Check` requires no *additional* errors versus when allowed, so
 * the callback re-fires after every process start and can re-fire per host.
 *
 * Note what is deliberately NOT an input: `SslError.primaryError`.
 * `localHostnames()` at internal/server/tls.go:111-124 puts only `localhost`,
 * `127.0.0.1`, the short `os.Hostname()` and non-loopback IPv4 addresses into
 * the certificate's SANs - IPv6 is filtered out entirely, and a MagicDNS name
 * appears only if it was the host of `--public-url` on first run. So
 * `SSL_IDMISMATCH` layered on `SSL_UNTRUSTED` is the NORMAL case on a tailnet,
 * and any handler that consults `primaryError` or `hasError()` rejects every
 * legitimate connection. `SSL_EXPIRED` is likewise accepted when the pin
 * matches and surfaced as a banner, matching the agent's
 * `InsecureSkipVerify: true` + pin-only `VerifyPeerCertificate` at
 * internal/agent/conn.go:29-43.
 */
class TrustStore(entries: List<ServerEntry>) {

    /**
     * Host-scoped, lower-cased. Entries are keyed by host alone, deliberately:
     * the pin must be found by the host of the URL that raised the error, and
     * nothing else about that URL may influence the lookup.
     */
    private val byHost: Map<String, ServerEntry> =
        entries.associateBy { it.host.lowercase() }

    val hosts: Set<String> get() = byHost.keys

    fun entryFor(host: String?): ServerEntry? = byHost[host?.lowercase()]

    fun evaluate(url: String?, der: ByteArray?, host: String?): Decision {
        val h = host?.lowercase()?.takeIf { it.isNotEmpty() }
            ?: return Decision.Rejected(Failure.NoHost(url ?: ""))
        val e = byHost[h]
            ?: return Decision.Rejected(Failure.UnknownHost(h))
        // An empty pin means system trust, and a publicly-trusted leaf raises no
        // SSL error at all. Reaching here for a SYSTEM entry is a real failure.
        if (e.trustMode == TrustMode.SYSTEM) return Decision.Rejected(Failure.UnknownHost(h))
        val bytes = der ?: return Decision.Rejected(Failure.NoCertificate)
        val got = Fingerprint.ofDer(bytes)
        return if (Fingerprint.matches(got, e.pinHex)) {
            Decision.Trusted
        } else {
            Decision.Rejected(Failure.PinMismatch(h, got, e.pinHex))
        }
    }

    companion object {
        val EMPTY = TrustStore(emptyList())

        /** A store holding exactly one entry - what `PinnedHttp` evaluates against. */
        fun of(entry: ServerEntry) = TrustStore(listOf(entry))
    }
}
