package io.github.monstercouch.homelabrmm.trust

import java.util.Base64

/**
 * A fixed, real certificate DER and the fingerprint Go computes for it.
 *
 * Generated once with `crypto/x509.CreateCertificate` shaped like
 * `internal/server/tls.go` (P-256, self-signed, SANs localhost /
 * DESKTOP-EQE8HAP / 127.0.0.1) and hashed with the very same expression the
 * server uses at internal/server/tls.go:45-49:
 *
 *   sum := sha256.Sum256(der); hex.EncodeToString(sum[:])
 *
 * If [GO_FINGERPRINT] ever stops matching `Fingerprint.ofDer(DER)`, the phone
 * has stopped agreeing with the server and every agent about what a pin is.
 */
object TestVectors {

    private const val DER_B64 =
        "MIIBoTCCAUegAwIBAgIBATAKBggqhkjOPQQDAjAWMRQwEgYDVQQDEwtob21lbGFiLXJtbTAeFw0y" +
            "MzExMTQyMjEzMjBaFw0zMzA1MTgwMzMzMjBaMBYxFDASBgNVBAMTC2hvbWVsYWItcm1tMFkwEwYH" +
            "KoZIzj0CAQYIKoZIzj0DAQcDQgAE5wFN4QH+L0xlVgZ6ObiZr4TlsRYVQsWIaSzypHVICpRy7m9N" +
            "zT1TvHyg7B4rZTKBhKpb79ZziA4334BEtQIq16OBhTCBgjAOBgNVHQ8BAf8EBAMCAoQwEwYDVR0l" +
            "BAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU77A9eV6mU6YVAHxVWBHS" +
            "95jxcrQwKwYDVR0RBCQwIoIJbG9jYWxob3N0gg9ERVNLVE9QLUVRRThIQVCHBH8AAAEwCgYIKoZI" +
            "zj0EAwIDSAAwRQIhAMlhEB91JrkoUM94YA2/lsFWvYcfJRJL7iEIjmZHLrFjAiABu30WAr9zl+g7" +
            "m6fDAb0nIos6S9gnsbR4S3lel27law=="

    /** The leaf certificate DER, exactly the bytes Chromium hands Java. */
    val DER: ByteArray = Base64.getDecoder().decode(DER_B64)

    /** hex(sha256(DER)), computed by Go. */
    const val GO_FINGERPRINT = "a84c9099c38e0482a03b5ffc21f2696a6019c808282cf2315e447e233f7ffca7"

    /** Universal SHA-256 vectors, as an independent cross-check of [Fingerprint.ofDer]. */
    const val SHA256_OF_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    const val SHA256_OF_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    fun pinnedEntry(
        host: String = "rmm.tail-scale.ts.net",
        port: Int = 8443,
        fp: String = GO_FINGERPRINT,
    ) = ServerEntry(
        id = "srv-1",
        label = "Homelab",
        url = "https://$host:$port",
        pinHex = fp,
        trustMode = TrustMode.PINNED,
    )

    fun systemEntry(host: String = "rmm.example.com", port: Int = 443) = ServerEntry(
        id = "srv-2",
        label = "Public",
        url = if (port == 443) "https://$host" else "https://$host:$port",
        pinHex = "",
        trustMode = TrustMode.SYSTEM,
    )
}
