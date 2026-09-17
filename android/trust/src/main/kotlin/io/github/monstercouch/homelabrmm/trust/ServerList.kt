package io.github.monstercouch.homelabrmm.trust

import java.nio.charset.StandardCharsets.UTF_8

/**
 * The on-disk form of the server list, and its plain-text escape hatch.
 *
 * Lives in `:trust` rather than in the app module so that the round trip is
 * covered by `./gradlew :trust:test` - the only automated gate on this machine -
 * and so that nothing in the sealed path depends on `org.json`, which is an
 * Android platform class and would drag the tests back onto a device.
 *
 * The encoded bytes are what `SealedCodec.seal` wraps.
 */
object ServerList {

    /** Bumped only for a format change that cannot be read by the old parser. */
    const val VERSION = 1

    fun encode(entries: List<ServerEntry>): ByteArray {
        val root = linkedMapOf<String, Any?>(
            "v" to VERSION.toLong(),
            "servers" to entries.map { e ->
                linkedMapOf<String, Any?>(
                    "id" to e.id,
                    "label" to e.label,
                    "url" to e.url,
                    "fp" to e.pinHex,
                    "trust" to e.trustMode.name,
                    "addedAt" to e.addedAt,
                    "lastConnectedAt" to e.lastConnectedAt,
                    "pinRotatedAt" to e.pinRotatedAt,
                )
            },
        )
        return Json.write(root).toByteArray(UTF_8)
    }

    /**
     * Parse bytes produced by [encode].
     *
     * Throws [IllegalArgumentException] on anything malformed. A caller that has
     * just successfully opened a GCM blob and then cannot parse it is looking at
     * a format problem, not an attack - but it still has no usable list, so the
     * recovery is the same: wipe and re-pair.
     */
    fun decode(bytes: ByteArray): List<ServerEntry> {
        val root = Json.read(String(bytes, UTF_8)) as? Map<*, *>
            ?: throw IllegalArgumentException("server list is not a JSON object")
        val v = (root["v"] as? Long) ?: throw IllegalArgumentException("server list has no version")
        require(v == VERSION.toLong()) { "unsupported server list version $v" }
        val servers = (root["servers"] as? List<*>)
            ?: throw IllegalArgumentException("server list has no servers array")
        return servers.map { raw ->
            val o = raw as? Map<*, *> ?: throw IllegalArgumentException("server entry is not an object")
            val fp = str(o, "fp")
            val trust = when (str(o, "trust")) {
                TrustMode.PINNED.name -> TrustMode.PINNED
                TrustMode.SYSTEM.name -> TrustMode.SYSTEM
                else -> TrustMode.forPin(fp)
            }
            require(trust == TrustMode.forPin(fp)) {
                "server entry ${str(o, "id")} declares $trust but its fingerprint says otherwise"
            }
            ServerEntry(
                id = str(o, "id"),
                label = str(o, "label"),
                url = str(o, "url"),
                pinHex = fp,
                trustMode = trust,
                addedAt = num(o, "addedAt"),
                lastConnectedAt = num(o, "lastConnectedAt"),
                pinRotatedAt = num(o, "pinRotatedAt"),
            )
        }
    }

    /**
     * The "Export server list" escape hatch (docs/ANDROID.md §2.3).
     *
     * The AndroidKeyStore key dies with an uninstall or a signing-identity
     * change; re-pairing must not be a scavenger hunt through the console. Plain
     * text, url + fp + label, in the order a human reads them - and the same
     * `homelabrmm://pair` URI, so the list can be walked straight back in.
     */
    fun exportText(entries: List<ServerEntry>): String = buildString {
        appendLine("# Homelab RMM - server list export")
        appendLine("# Each fingerprint is the SHA-256 of the server's leaf certificate DER,")
        appendLine("# the same 64 hex characters the console shows on its Settings page.")
        appendLine("# Re-check every fingerprint out of band before pairing from this file.")
        if (entries.isEmpty()) {
            appendLine()
            appendLine("(no servers)")
            return@buildString
        }
        for (e in entries) {
            appendLine()
            appendLine("label: ${e.label}")
            appendLine("url:   ${e.url}")
            appendLine("trust: ${e.trustMode.name.lowercase()}")
            appendLine("fp:    ${if (e.pinHex.isEmpty()) "(system trust - no pin)" else e.pinHex}")
            appendLine("link:  ${PairUri.build(e.url, e.pinHex, e.label)}")
        }
    }

    private fun str(o: Map<*, *>, k: String): String = (o[k] as? String).orEmpty()

    private fun num(o: Map<*, *>, k: String): Long = when (val v = o[k]) {
        is Long -> v
        is Double -> v.toLong()
        else -> 0L
    }
}

/**
 * A deliberately tiny JSON reader/writer for exactly the shapes [ServerList]
 * emits: objects, arrays, strings, integers and booleans. Strict on input -
 * trailing data, control characters in strings and bad escapes are all errors.
 */
internal object Json {

    fun write(value: Any?): String = StringBuilder().also { writeTo(it, value) }.toString()

    private fun writeTo(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is String -> writeString(sb, value)
            is Boolean -> sb.append(if (value) "true" else "false")
            is Long, is Int -> sb.append(value.toString())
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, v) in value) {
                    if (!first) sb.append(',')
                    first = false
                    writeString(sb, k.toString())
                    sb.append(':')
                    writeTo(sb, v)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                for ((i, v) in value.withIndex()) {
                    if (i > 0) sb.append(',')
                    writeTo(sb, v)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("cannot encode ${value.javaClass.name} as JSON")
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append("\\u").append(String.format("%04x", c.code))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }

    fun read(text: String): Any? {
        val p = Parser(text)
        val v = p.value()
        p.skipWs()
        require(p.atEnd()) { "trailing data at offset ${p.pos}" }
        return v
    }

    private class Parser(private val s: String) {
        var pos = 0

        fun atEnd() = pos >= s.length

        fun skipWs() {
            while (pos < s.length && s[pos].let { it == ' ' || it == '\t' || it == '\n' || it == '\r' }) pos++
        }

        fun value(): Any? {
            skipWs()
            require(pos < s.length) { "unexpected end of JSON" }
            return when (s[pos]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> number()
            }
        }

        private fun literal(word: String, v: Any?): Any? {
            require(s.startsWith(word, pos)) { "bad literal at offset $pos" }
            pos += word.length
            return v
        }

        private fun obj(): Map<String, Any?> {
            expect('{')
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (peek() == '}') { pos++; return out }
            while (true) {
                skipWs()
                val k = string()
                skipWs()
                expect(':')
                out[k] = value()
                skipWs()
                when (val c = peek()) {
                    ',' -> pos++
                    '}' -> { pos++; return out }
                    else -> throw IllegalArgumentException("expected , or } at offset $pos, got '$c'")
                }
            }
        }

        private fun arr(): List<Any?> {
            expect('[')
            val out = ArrayList<Any?>()
            skipWs()
            if (peek() == ']') { pos++; return out }
            while (true) {
                out += value()
                skipWs()
                when (val c = peek()) {
                    ',' -> pos++
                    ']' -> { pos++; return out }
                    else -> throw IllegalArgumentException("expected , or ] at offset $pos, got '$c'")
                }
            }
        }

        private fun string(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                require(pos < s.length) { "unterminated string" }
                when (val c = s[pos++]) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        require(pos < s.length) { "unterminated escape" }
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                require(pos + 4 <= s.length) { "truncated \\u escape" }
                                sb.append(s.substring(pos, pos + 4).toInt(16).toChar())
                                pos += 4
                            }
                            else -> throw IllegalArgumentException("bad escape \\$e at offset ${pos - 1}")
                        }
                    }
                    else -> {
                        require(c >= ' ') { "raw control character in string at offset ${pos - 1}" }
                        sb.append(c)
                    }
                }
            }
        }

        private fun number(): Any {
            val start = pos
            if (peek() == '-') pos++
            while (pos < s.length && (s[pos].isDigit() || s[pos] in "+-.eE")) pos++
            val raw = s.substring(start, pos)
            require(raw.isNotEmpty()) { "expected a number at offset $start" }
            return raw.toLongOrNull()
                ?: raw.toDoubleOrNull()
                ?: throw IllegalArgumentException("bad number '$raw' at offset $start")
        }

        private fun peek(): Char {
            require(pos < s.length) { "unexpected end of JSON" }
            return s[pos]
        }

        private fun expect(c: Char) {
            require(pos < s.length && s[pos] == c) { "expected '$c' at offset $pos" }
            pos++
        }
    }
}
