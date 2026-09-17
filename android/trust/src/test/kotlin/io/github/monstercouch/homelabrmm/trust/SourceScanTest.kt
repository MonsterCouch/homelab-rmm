package io.github.monstercouch.homelabrmm.trust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source-level invariants on the trust path.
 *
 * These are unit tests over the checked-in source, not over compiled behaviour,
 * because the property being defended is structural: "there is exactly one place
 * in this application that can decide to trust a certificate, and no build
 * variant adds a second one". No runtime test can show the absence of a branch
 * that only exists in a debug build.
 */
class SourceScanTest {

    /** `app/src/main` and `trust/src/main` - every line that ships. */
    private val roots: List<File> by lazy {
        val root = androidRoot()
        listOf(File(root, "app/src/main"), File(root, "trust/src/main"))
    }

    private val sources: List<File> by lazy {
        roots.filter { it.isDirectory }
            .flatMap { it.walkTopDown().filter { f -> f.isFile && (f.extension == "kt" || f.extension == "java") } }
            .sortedBy { it.path }
    }

    @Test
    fun the_source_roots_exist_and_are_not_empty() {
        // If this ever passes vacuously, every other test in this class does too.
        assertTrue(
            "expected app/src/main and trust/src/main under ${androidRoot()}",
            roots.all { it.isDirectory },
        )
        assertTrue("no Kotlin/Java sources found to scan", sources.isNotEmpty())
    }

    @Test
    fun proceed_appears_exactly_once() {
        val hits = hits(Regex("""\.proceed\s*\("""))
        val sslClients = sources.filter { strip(it.readText()).contains("onReceivedSslError") }

        if (sslClients.isEmpty()) {
            // The single pin call site (task A6) has not landed yet. The
            // invariant that holds today, and must keep holding, is that nothing
            // else in the tree may call proceed() on an SslErrorHandler.
            assertEquals(
                "no onReceivedSslError override exists yet, so nothing may call proceed(): $hits",
                0,
                hits.size,
            )
            return
        }

        assertEquals(
            "handler.proceed() must occur exactly once in the whole tree, found: $hits",
            1,
            hits.size,
        )
        val where = hits.single().substringBefore(':')
        assertTrue(
            "the only proceed() must live in the file that overrides onReceivedSslError, found it in $where",
            sslClients.any { it.path.endsWith(where.replace('/', File.separatorChar)) || it.name == where },
        )
        assertEquals(
            "exactly one file may override onReceivedSslError, found: ${sslClients.map { it.name }}",
            1,
            sslClients.size,
        )
    }

    @Test
    fun no_build_variant_bypass_in_the_trust_path() {
        // Rule 4 of docs/ANDROID.md §2.2: no bypass exists, in any build variant.
        // The mismatch screen is a dead end - no "proceed anyway", no long-press
        // escape, no BuildConfig.DEBUG branch in the pin path.
        val trustPath = sources.filter { f ->
            val s = strip(f.readText())
            s.contains("onReceivedSslError") ||
                s.contains("checkServerTrusted") ||
                s.contains("TrustStore") ||
                s.contains("SslErrorHandler")
        }
        val offenders = trustPath.filter { f ->
            val s = strip(f.readText())
            s.contains("BuildConfig.DEBUG") || s.contains("isDebuggable") || s.contains("DEBUG_BYPASS")
        }
        assertTrue(
            "no build-variant branch may exist in the trust path, found in ${offenders.map { it.name }}",
            offenders.isEmpty(),
        )
    }

    @Test
    fun no_blanket_trust_manager_anywhere() {
        // A TrustManager whose checkServerTrusted body is empty is the classic
        // "fix" for a self-signed certificate and would silently delete the pin.
        val hits = hits(Regex("""(TrustAllCerts|X509ExtendedTrustManager|allowAllHostnames|NO_VERIFY)"""))
        assertTrue("suspicious trust plumbing: $hits", hits.isEmpty())
    }

    @Test
    fun hostname_verification_is_disabled_only_where_it_is_justified() {
        // `hostnameVerifier { _, _ -> true }` is safe ONLY because the pin is
        // exact, and it will trip any security scanner - so every occurrence has
        // to carry the reference to internal/server/tls.go:111-124 that explains
        // why the certificate's SANs cannot cover a tailnet name.
        val files = sources.filter { strip(it.readText()).contains("HostnameVerifier") }
        for (f in files) {
            val text = f.readText()
            assertTrue(
                "${f.name} disables hostname verification without citing internal/server/tls.go",
                text.contains("tls.go:111-124"),
            )
            assertTrue(
                "${f.name} disables hostname verification without citing docs/ANDROID.md",
                text.contains("docs/ANDROID.md"),
            )
        }
    }

    @Test
    fun no_service_worker_is_ever_registered_from_the_shell() {
        // docs/ANDROID.md §2.2 rule 7: ssl_manager.cc:132 denies with no client
        // callback when there is no WebContents, and the comment names service
        // workers. A service worker would make the pin unreachable.
        val hits = hits(Regex("""(ServiceWorkerController|ServiceWorkerClient|serviceWorker)"""))
        assertTrue("the shell must never involve a service worker: $hits", hits.isEmpty())
    }

    private fun hits(re: Regex): List<String> = buildList {
        for (f in sources) {
            val code = strip(f.readText())
            code.lineSequence().forEachIndexed { i, line ->
                if (re.containsMatchIn(line)) add("${f.name}:${i + 1}: ${line.trim()}")
            }
        }
    }

    /**
     * Blank out comments and string literals, preserving line structure, so a
     * KDoc paragraph that discusses `handler.proceed()` does not count as a call
     * site and a log message cannot hide one.
     */
    private fun strip(src: String): String {
        val out = StringBuilder(src.length)
        var i = 0
        while (i < src.length) {
            val c = src[i]
            when {
                c == '/' && i + 1 < src.length && src[i + 1] == '/' -> {
                    while (i < src.length && src[i] != '\n') { out.append(' '); i++ }
                }
                c == '/' && i + 1 < src.length && src[i + 1] == '*' -> {
                    var depth = 1
                    out.append("  "); i += 2
                    while (i < src.length && depth > 0) {
                        if (src.startsWith("/*", i)) { depth++; out.append("  "); i += 2 }
                        else if (src.startsWith("*/", i)) { depth--; out.append("  "); i += 2 }
                        else { out.append(if (src[i] == '\n') '\n' else ' '); i++ }
                    }
                }
                src.startsWith("\"\"\"", i) -> {
                    out.append("   "); i += 3
                    while (i < src.length && !src.startsWith("\"\"\"", i)) {
                        out.append(if (src[i] == '\n') '\n' else ' '); i++
                    }
                    if (i < src.length) { out.append("   "); i += 3 }
                }
                c == '"' -> {
                    out.append(' '); i++
                    while (i < src.length && src[i] != '"') {
                        if (src[i] == '\\' && i + 1 < src.length) { out.append("  "); i += 2 }
                        else { out.append(if (src[i] == '\n') '\n' else ' '); i++ }
                    }
                    if (i < src.length) { out.append(' '); i++ }
                }
                else -> { out.append(c); i++ }
            }
        }
        return out.toString()
    }

    private fun androidRoot(): File {
        System.getProperty("rmm.android.root")?.let { return File(it) }
        var d: File? = File(System.getProperty("user.dir"))
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile && File(d, "trust").isDirectory) return d
            d = d.parentFile
        }
        throw IllegalStateException("cannot locate the android/ build root from ${System.getProperty("user.dir")}")
    }
}
