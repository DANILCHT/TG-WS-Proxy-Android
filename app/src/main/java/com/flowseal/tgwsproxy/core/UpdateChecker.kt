package com.flowseal.tgwsproxy.core

import com.flowseal.tgwsproxy.net.HttpLite

/**
 * Checks the GitHub Releases API for a newer APK.
 *
 * The parsing and comparison halves are deliberately free of Android APIs so
 * they can be unit-tested on the JVM; only [check] touches the network.
 */
object UpdateChecker {

    /** Latest-release endpoint of the repository this app is published from. */
    const val RELEASES_API =
        "https://api.github.com/repos/DANILCHT/TG-WS-Proxy-Android/releases/latest"

    const val RELEASES_PAGE =
        "https://github.com/DANILCHT/TG-WS-Proxy-Android/releases/latest"

    private const val MAX_BODY = 512 * 1024
    private const val TIMEOUT_MS = 15_000

    class Release(
        val version: String,
        val apkUrl: String,
        val notes: String,
        val sizeBytes: Long,
        /** Lowercase hex SHA-256 of the APK when GitHub reports it, else null. */
        val sha256: String? = null,
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
        val body = runCatching {
            val resp = HttpLite.request(
                HttpLite.Request(
                    url = RELEASES_API,
                    timeoutMs = TIMEOUT_MS,
                    headers = mapOf("Accept" to "application/vnd.github+json"),
                    maxBytes = MAX_BODY,
                )
            )
            if (resp.status != 200) throw java.io.IOException("HTTP ${resp.status}")
            resp.text()
        }.onFailure { Logger.d("Update check failed: $it") }.getOrNull()
        lastCheckFailed = body == null
        if (body == null) return null

        val release = parse(body) ?: return null
        if (!isNewer(release.version, currentVersion)) return null
        return release
    }

    /** Extracts the release info from the GitHub API payload. */
    fun parse(json: String): Release? {
        val root = runCatching { MiniJson.parse(json) }.getOrNull() as? Map<*, *> ?: return null
        val tag = root["tag_name"] as? String ?: return null
        if (root["draft"] == true || root["prerelease"] == true) return null
        val assets = root["assets"] as? List<*> ?: return null

        // Prefer an asset literally named *.apk; among several, the release build.
        val apks = assets.mapNotNull { it as? Map<*, *> }.filter { a ->
            val url = a["browser_download_url"] as? String ?: return@filter false
            url.startsWith("https://") && url.endsWith(".apk", ignoreCase = true)
        }
        val apk = apks.firstOrNull { (it["name"] as? String)?.contains("release") == true }
            ?: apks.firstOrNull() ?: return null

        val digest = (apk["digest"] as? String)?.lowercase()
            ?.removePrefix("sha256:")
            ?.takeIf { d -> d.length == 64 && d.all { it in '0'..'9' || it in 'a'..'f' } }

        return Release(
            version = normalize(tag),
            apkUrl = apk["browser_download_url"] as String,
            notes = root["body"] as? String ?: "",
            sizeBytes = (apk["size"] as? Number)?.toLong() ?: 0L,
            sha256 = digest,
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
}
