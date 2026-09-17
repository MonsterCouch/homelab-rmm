package io.github.monstercouch.homelabrmm.net

import android.util.Log
import io.github.monstercouch.homelabrmm.trust.Decision
import io.github.monstercouch.homelabrmm.trust.Fingerprint
import io.github.monstercouch.homelabrmm.trust.ServerEntry
import io.github.monstercouch.homelabrmm.trust.TrustMode
import io.github.monstercouch.homelabrmm.trust.TrustStore
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * The native HTTP client for the four things the WebView cannot do for us:
 * the pairing probe, file downloads, a real sign-out, and the Connection test's
 * native WebSocket row.
 *
 * `HttpsURLConnection`, not OkHttp: two call sites do not justify the
 * dependency, and the pinning surface is smaller with the platform stack.
 *
 * Trust comes from exactly the same [TrustStore] the WebView's
 * `onReceivedSslError` consults. One `evaluate()`, two call paths - two copies
 * is exactly how two copies drift.
 */
object PinnedHttp {

    private const val TAG = "PinnedHttp"

    /** Identifies this client in `sessions.user_agent` and in the audit log. */
    const val REQUESTED_WITH = "rmm-android"

    const val DEFAULT_TIMEOUT_MS = 10_000
    const val PROBE_TIMEOUT_MS = 2_000

    private const val MAX_BODY_BYTES = 512 * 1024

    // ---------------------------------------------------------------------
    // Results
    // ---------------------------------------------------------------------

    data class LeafInfo(
        val fingerprint: String,
        val subject: String,
        val issuer: String,
        val notBefore: Long,
        val notAfter: Long,
    ) {
        val expired: Boolean get() = System.currentTimeMillis() > notAfter
    }

    data class Response(
        val code: Int,
        val body: String,
        val headers: Map<String, List<String>>,
        val leaf: LeafInfo?,
    ) {
        val ok: Boolean get() = code in 200..299
    }

    /** `GET /api/auth/state`, the one endpoint that answers unauthenticated. */
    data class AuthState(
        val needsSetup: Boolean,
        val setupCodeRequired: Boolean,
        val user: String?,
        val version: String,
        val leaf: LeafInfo?,
    ) {
        val signedIn: Boolean get() = user != null

        /** Where the first load should land, per the reply. */
        val firstPath: String
            get() = when {
                needsSetup -> "/setup"
                signedIn -> "/"
                else -> "/login"
            }
    }

    /** The raw `Upgrade:` probe - row 5 of the Connection test. */
    data class UpgradeResult(
        val status: Int,
        val statusLine: String,
        val leaf: LeafInfo?,
        val error: String? = null,
    )

    /**
     * The presented leaf did not match the stored pin. Carries both values so
     * the mismatch screen can show them side by side in 4x4 groups.
     */
    class PinFailure(
        val host: String,
        val presented: String?,
        val expected: String,
    ) : IOException(
        "certificate fingerprint mismatch for $host: presented ${presented ?: "(none)"}, expected $expected"
    )

    // ---------------------------------------------------------------------
    // Requests
    // ---------------------------------------------------------------------

    /**
     * Unauthenticated `GET /api/auth/state`.
     *
     * A GET, so it needs no `X-Requested-With`, no Origin and no Content-Type.
     * This is what Trust review runs before anything is stored: you cannot store
     * a pin you have not successfully used.
     */
    @Throws(IOException::class)
    fun probeAuthState(entry: ServerEntry, timeoutMs: Int = PROBE_TIMEOUT_MS): AuthState {
        val r = get(entry, "/api/auth/state", cookie = null, timeoutMs = timeoutMs)
        if (!r.ok) throw IOException("GET /api/auth/state returned HTTP ${r.code}")
        val o = try {
            JSONObject(r.body)
        } catch (e: Exception) {
            throw IOException("GET /api/auth/state did not return JSON", e)
        }
        // `user` is an object when signed in and JSON null otherwise.
        val user = o.optJSONObject("user")?.optString("username")?.takeIf { it.isNotEmpty() }
        return AuthState(
            needsSetup = o.optBoolean("needs_setup", false),
            setupCodeRequired = o.optBoolean("setup_code_required", false),
            user = user,
            version = o.optString("version", ""),
            leaf = r.leaf,
        )
    }

    @Throws(IOException::class)
    fun get(
        entry: ServerEntry,
        path: String,
        cookie: String? = null,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    ): Response = request(entry, "GET", path, cookie, timeoutMs)

    /**
     * A real sign-out: `POST /api/auth/logout` carrying the WebView's cookie and
     * `X-Requested-With`, **with no body**.
     *
     * The absent Content-Type is exactly what satisfies `authGuard`'s check at
     * internal/server/api.go:317-322 - it only rejects a Content-Type that is
     * present and not application/json.
     *
     * `CookieManager.removeSessionCookies()` alone is NOT a substitute: it
     * leaves the server-side session row alive for the full 14 days
     * (`sessionTTL = 14*24h`, and `userBySession` never extends `expires_at`).
     * Nor is an `evaluateJavascript` click on the console's own Sign-out button,
     * which is brittle DOM coupling to markup the mobile pass is changing.
     */
    @Throws(IOException::class)
    fun logout(entry: ServerEntry, cookie: String?, timeoutMs: Int = DEFAULT_TIMEOUT_MS): Response =
        request(entry, "POST", "/api/auth/logout", cookie, timeoutMs)

    @Throws(IOException::class)
    private fun request(
        entry: ServerEntry,
        method: String,
        path: String,
        cookie: String?,
        timeoutMs: Int,
    ): Response {
        val pin = PinTrust(entry)
        val conn = open(entry, entry.urlFor(path), pin, timeoutMs)
        try {
            conn.requestMethod = method
            conn.doOutput = false
            if (method != "GET" && method != "HEAD") {
                // All `requireUser` checks is that the header is non-empty
                // (internal/server/auth.go:340). No Origin is sent: `sameOrigin`
                // treats an absent Origin as allowed, and no Content-Type is set
                // because a body-less POST must not look like a form post.
                conn.setRequestProperty("X-Requested-With", REQUESTED_WITH)
                conn.setFixedLengthStreamingMode(0)
            }
            if (!cookie.isNullOrEmpty()) conn.setRequestProperty("Cookie", cookie)
            conn.setRequestProperty("Accept", "application/json")

            val code = conn.responseCode
            val body = (if (code in 200..399) conn.inputStream else conn.errorStream)
                ?.use { readBody(it) } ?: ""
            return Response(code, body, conn.headerFields.orEmpty(), leafOf(conn))
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            throw pin.failureOr(entry, e)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Stream a download through the pinned client and hand the bytes to [sink].
     *
     * `android.app.DownloadManager` is prohibited for this (docs/ANDROID.md
     * §2.6): it runs in a system process against the **system trust store**, so
     * it never reaches `onReceivedSslError` and fails on the self-signed leaf,
     * and it has a **separate cookie jar**, so it 401s without a copied header.
     *
     * [cookie] comes from `CookieManager.getInstance().getCookie(url)` and
     * [userAgent] from the WebView, so the server sees the same client it
     * issued the session to.
     */
    @Throws(IOException::class)
    fun download(
        entry: ServerEntry,
        url: String,
        cookie: String?,
        userAgent: String?,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        sink: (stream: InputStream, contentType: String?, contentLength: Long, disposition: String?) -> Unit,
    ) {
        require(sameOrigin(entry, url)) { "refusing to download from another origin: $url" }
        val pin = PinTrust(entry)
        val conn = open(entry, url, pin, timeoutMs)
        try {
            conn.requestMethod = "GET"
            if (!cookie.isNullOrEmpty()) conn.setRequestProperty("Cookie", cookie)
            if (!userAgent.isNullOrEmpty()) conn.setRequestProperty("User-Agent", userAgent)
            val code = conn.responseCode
            if (code !in 200..299) {
                conn.errorStream?.use { readBody(it) }
                throw IOException("download returned HTTP $code")
            }
            BufferedInputStream(conn.inputStream).use { s ->
                sink(
                    s,
                    conn.contentType,
                    conn.getHeaderFieldLong("Content-Length", -1L),
                    conn.getHeaderField("Content-Disposition"),
                )
            }
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            throw pin.failureOr(entry, e)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Row 5 of the Connection test: issue a raw WebSocket `Upgrade:` request and
     * read the status code directly.
     *
     * Deliberately an [SSLSocket] rather than [HttpsURLConnection]: the platform
     * URL stack owns the `Connection` and `Upgrade` headers and will not let a
     * caller set them, and the whole point of this row is to see the server's
     * own status line. Against `/ws/shell/__rmm_pin_probe__` the expected answer
     * is **409** - `handleShellWS` checks `sameOrigin` and then
     * `if !s.hub.IsOnline(agentID) { writeErr(w, 409, "agent is offline") }`
     * BEFORE `upgrader.Upgrade`, so an unknown id can never spawn a shell and
     * nothing is audited as a session.
     *
     * Proving reachability here, independently of the WebView, is what lets a
     * row-4 failure be attributed to the WebView's network stack rather than to
     * the tailnet.
     */
    fun upgradeProbe(
        entry: ServerEntry,
        path: String = "/ws/shell/__rmm_pin_probe__",
        cookie: String? = null,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    ): UpgradeResult {
        val pin = PinTrust(entry)
        var socket: Socket? = null
        return try {
            val factory: SSLSocketFactory = if (entry.trustMode == TrustMode.SYSTEM) {
                SSLSocketFactory.getDefault() as SSLSocketFactory
            } else {
                pinnedContext(pin).socketFactory
            }
            val plain = Socket()
            socket = plain
            plain.connect(InetSocketAddress(entry.host, entry.port), timeoutMs)
            plain.soTimeout = timeoutMs
            val ssl = factory.createSocket(plain, entry.host, entry.port, true) as SSLSocket
            socket = ssl
            if (entry.trustMode == TrustMode.SYSTEM) {
                // With no pin, the hostname is the only identity there is, so
                // ask the platform to verify it during the handshake.
                ssl.sslParameters = ssl.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            }
            ssl.startHandshake()

            val key = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val req = buildString {
                append("GET ").append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(hostHeader(entry)).append("\r\n")
                append("Upgrade: websocket\r\n")
                append("Connection: Upgrade\r\n")
                append("Sec-WebSocket-Version: 13\r\n")
                append("Sec-WebSocket-Key: ").append(Base64.getEncoder().encodeToString(key)).append("\r\n")
                // No Origin: `sameOrigin` at internal/server/relay.go:30-39
                // treats an absent Origin as allowed, and sending one we would
                // have to keep byte-identical to Host is a needless way to fail.
                if (!cookie.isNullOrEmpty()) append("Cookie: ").append(cookie).append("\r\n")
                append("User-Agent: ").append(REQUESTED_WITH).append("\r\n")
                append("\r\n")
            }
            ssl.outputStream.write(req.toByteArray(Charsets.ISO_8859_1))
            ssl.outputStream.flush()

            val line = readStatusLine(ssl.inputStream)
            val status = line.split(' ').getOrNull(1)?.toIntOrNull() ?: -1
            UpgradeResult(status, line, leafOf(ssl))
        } catch (e: Exception) {
            val f = pin.failure()
            UpgradeResult(
                status = -1,
                statusLine = "",
                leaf = pin.seen?.let(::leafInfo),
                error = f?.message ?: e.toString(),
            )
        } finally {
            runCatching { socket?.close() }
        }
    }

    // ---------------------------------------------------------------------
    // Plumbing
    // ---------------------------------------------------------------------

    private fun open(
        entry: ServerEntry,
        url: String,
        pin: PinTrust,
        timeoutMs: Int,
    ): HttpsURLConnection {
        val conn = URL(url).openConnection() as HttpsURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        // A redirect can never inherit a pin, and this client never follows one
        // blindly: `Location` is surfaced to the caller instead.
        conn.instanceFollowRedirects = false
        conn.useCaches = false

        if (entry.trustMode == TrustMode.SYSTEM) {
            // Empty pin: platform default socket factory and default hostname
            // verifier. System trust, no bypass, nothing weakened.
            return conn
        }

        conn.sslSocketFactory = pinnedContext(pin).socketFactory
        // SAFE ONLY BECAUSE THE PIN IS EXACT.
        //
        // The server's self-signed certificate covers only what
        // `localHostnames()` returns at internal/server/tls.go:111-124:
        // `localhost`, `127.0.0.1`, the short `os.Hostname()`, and non-loopback
        // IPv4 addresses. IPv6 is filtered out entirely and a MagicDNS name
        // appears only if it was the host of `--public-url` on first run. So the
        // SANs will not cover the tailnet name the operator actually types, and
        // hostname verification would reject every legitimate connection.
        //
        // The identity check has not been removed, it has been replaced by a
        // stronger one: PinTrust below compares the SHA-256 of the leaf DER
        // against a fingerprint a human confirmed out of band. See
        // docs/ANDROID.md §2.2 rule 1 and §5.3, and note that this mirrors the
        // agent's own `InsecureSkipVerify: true` plus pin-only
        // `VerifyPeerCertificate` at internal/agent/conn.go:29-43.
        conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
        return conn
    }

    private fun pinnedContext(pin: PinTrust): SSLContext =
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(pin), SecureRandom())
        }

    /**
     * A plain [X509TrustManager], NOT an `X509ExtendedTrustManager`.
     *
     * The extended class is abstract with four further methods, including
     * `checkServerTrusted(chain, authType, Socket)` and `(..., SSLEngine)`, so
     * an object overriding only the two-argument form would not compile.
     * Conscrypt invokes the two-argument form for a non-extended manager, which
     * is exactly the surface we want to audit.
     */
    private class PinTrust(private val entry: ServerEntry) : X509TrustManager {

        private val trust = TrustStore.of(entry)

        /** The leaf the server actually presented, for the mismatch screen. */
        @Volatile
        var seen: X509Certificate? = null
            private set

        @Volatile
        private var mismatch: PinFailure? = null

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val leaf = chain.firstOrNull()
            seen = leaf
            val d = trust.evaluate(entry.url, leaf?.encoded, entry.host)
            if (d !is Decision.Trusted) {
                mismatch = PinFailure(
                    host = entry.host,
                    presented = leaf?.encoded?.let(Fingerprint::ofDer),
                    expected = entry.pinHex,
                )
                throw CertificateException("certificate fingerprint mismatch")
            }
        }

        /** Never `= Unit`. This client is not a server and authenticates no one. */
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String): Unit =
            throw CertificateException("this client never authenticates a peer")

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

        fun failure(): PinFailure? = mismatch

        /** Surface the pin failure rather than a generic handshake error. */
        fun failureOr(entry: ServerEntry, cause: Exception): IOException =
            mismatch ?: IOException("TLS handshake with ${entry.host} failed: ${cause.message}", cause)
    }

    private fun leafOf(conn: HttpsURLConnection): LeafInfo? = runCatching {
        (conn.serverCertificates.firstOrNull() as? X509Certificate)?.let(::leafInfo)
    }.getOrNull()

    private fun leafOf(socket: SSLSocket): LeafInfo? = runCatching {
        (socket.session.peerCertificates.firstOrNull() as? X509Certificate)?.let(::leafInfo)
    }.getOrNull()

    private fun leafInfo(cert: X509Certificate) = LeafInfo(
        fingerprint = Fingerprint.ofDer(cert.encoded),
        subject = cert.subjectX500Principal.name,
        issuer = cert.issuerX500Principal.name,
        notBefore = cert.notBefore.time,
        notAfter = cert.notAfter.time,
    )

    private fun hostHeader(entry: ServerEntry): String =
        if (entry.port == 443) entry.host else "${entry.host}:${entry.port}"

    private fun sameOrigin(entry: ServerEntry, url: String): Boolean = runCatching {
        val u = URL(url)
        val port = if (u.port == -1) u.defaultPort else u.port
        u.protocol.equals("https", true) && u.host.equals(entry.host, true) && port == entry.port
    }.getOrDefault(false)

    private fun readBody(stream: InputStream): String {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8 * 1024)
        var total = 0
        while (true) {
            val n = stream.read(buf)
            if (n < 0) break
            total += n
            if (total > MAX_BODY_BYTES) {
                Log.w(TAG, "response body exceeded $MAX_BODY_BYTES bytes; truncating")
                out.write(buf, 0, n - (total - MAX_BODY_BYTES))
                break
            }
            out.write(buf, 0, n)
        }
        return out.toString(Charsets.UTF_8.name())
    }

    /** Read one CRLF-terminated status line without pulling in the body. */
    private fun readStatusLine(stream: InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 1024) {
            val c = stream.read()
            if (c < 0) break
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    /** True when a throwable is this client's own pin rejection. */
    fun isPinFailure(e: Throwable?): Boolean = e is PinFailure
}
