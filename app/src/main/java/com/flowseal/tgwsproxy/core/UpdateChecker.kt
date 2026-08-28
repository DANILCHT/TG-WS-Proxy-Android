package com.flowseal.tgwsproxy.core

import java.net.HttpURLConnection
import java.net.URL

/**
 * Checks the GitHub Releases API for a newer APK.
 *
 * The parsing and comparison halves are deliberately free of Android APIs so
 * they can be unit-tested on the JVM; only [fetch] touches the network.
 */
object UpdateChecker {

    /** Latest-release endpoint of the repository this app is published from. */
    const val RELEASES_API =
        "https://api.github.com/repos/DANILCHT/TG-WS-Proxy-Android/releases/latest"

    const val RELEASES_PAGE =
        "https://github.com/DANILCHT/TG-WS-Proxy-Android/releases/latest"

    private const val MAX_BODY = 512 * 1024
    private const val TIMEOUT_MS = 10_000

    class Release(
        val version: String,
        val apkUrl: String,
        val notes: String,
        val sizeBytes: Long,
    )

    /** True when the last [check] could not reach GitHub at all. */
    @Volatile
    var lastCheckFailed: Boolean = false
        private set

    /**
     * Returns the newest release when it is newer than [currentVersion], or null
     * when up to date, unreachable or the release carries no APK.
     */
    fun check(currentVersion: String): Release? {
        val body = runCatching { fetch(URL(RELEASES_API)) }
            .onFailure { Logger.d("Update check failed: $it") }
            .getOrNull()
        lastCheckFailed = body == null
        if (body == null) return null

        val release = parse(body) ?: return null
        if (!isNewer(release.version, currentVersion)) return null
        return release
    }

    /** Extracts the release info from the GitHub API payload. */
    fun parse(json: String): Release? {
        val tag = stringField(json, "tag_name") ?: return null
        val apk = firstApkUrl(json) ?: return null
        return Release(
            version = normalize(tag),
            apkUrl = apk,
            notes = stringField(json, "body").orEmpty(),
            sizeBytes = apkSize(json),
        )
    }

    /**
     * Compares dotted numeric versions. Extra trailing components count, so
     * 1.0.1 > 1.0 and 1.10 > 1.9. Non-numeric parts are ignored, which keeps
     * suffixes like "1.2.0-beta" from breaking the comparison.
     */
    fun isNewer(candidate: String, current: String): Boolean {
        val a = versionParts(candidate)
        val b = versionParts(current)
        if (a.isEmpty()) return false
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    /** Strips a leading "v" and any surrounding whitespace. */
    fun normalize(tag: String): String =
        tag.trim().removePrefix("v").removePrefix("V").trim()

    private fun versionParts(v: String): List<Int> =
        normalize(v)
            .split('.', '-', '+', '_')
            .mapNotNull { part -> part.takeWhile { it.isDigit() }.toIntOrNull() }

    // --------------------------------------------------------------- JSON bits

    /**
     * Minimal string-field reader. A full JSON parser is overkill for two
     * fields, and org.json is not available in unit tests.
     */
    internal fun stringField(json: String, name: String): String? {
        val key = "\"$name\""
        var i = json.indexOf(key)
        while (i >= 0) {
            var p = i + key.length
            while (p < json.length && json[p].isWhitespace()) p++
            if (p < json.length && json[p] == ':') {
                p++
                while (p < json.length && json[p].isWhitespace()) p++
                if (p < json.length && json[p] == '"') return readString(json, p + 1)
                return null
            }
            i = json.indexOf(key, i + 1)
        }
        return null
    }

    private fun readString(json: String, start: Int): String {
        val sb = StringBuilder()
        var p = start
        while (p < json.length) {
            val c = json[p]
            if (c == '\\' && p + 1 < json.length) {
                when (val esc = json[p + 1]) {
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> {
                        if (p + 5 < json.length) {
                            val hex = json.substring(p + 2, p + 6)
                            hex.toIntOrNull(16)?.let { sb.append(it.toChar()) }
                            p += 4
                        }
                    }

                    else -> sb.append(esc)
                }
                p += 2
                continue
            }
            if (c == '"') break
            sb.append(c)
            p++
        }
        return sb.toString()
    }

    /** First browser_download_url ending in .apk. */
    internal fun firstApkUrl(json: String): String? {
        val key = "\"browser_download_url\""
        var i = json.indexOf(key)
        while (i >= 0) {
            val quote = json.indexOf('"', json.indexOf(':', i + key.length) + 1)
            if (quote < 0) return null
            val url = readString(json, quote + 1)
            if (url.endsWith(".apk", ignoreCase = true) && url.startsWith("https://")) {
                return url
            }
            i = json.indexOf(key, i + 1)
        }
        return null
    }

    private fun apkSize(json: String): Long {
        val i = json.indexOf("\"size\"")
        if (i < 0) return 0
        val colon = json.indexOf(':', i)
        if (colon < 0) return 0
        val digits = json.drop(colon + 1).trimStart().takeWhile { it.isDigit() }
        return digits.toLongOrNull() ?: 0
    }

    // ------------------------------------------------------------------ network

    @Throws(Exception::class)
    private fun fetch(url: URL): String {
        val conn = NetworkBinder.openConnection(url) as HttpURLConnection
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        conn.setRequestProperty("User-Agent", "tg-ws-proxy-android")
        try {
            if (conn.responseCode != 200) {
                throw java.io.IOException("HTTP ${conn.responseCode}")
            }
            val sb = StringBuilder()
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                val buf = CharArray(8 * 1024)
                while (true) {
                    val n = reader.read(buf)
                    if (n <= 0) break
                    sb.append(buf, 0, n)
                    if (sb.length > MAX_BODY) break
                }
            }
            return sb.toString()
        } finally {
            conn.disconnect()
        }
    }
}
