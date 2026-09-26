package com.flowseal.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The update check drives an installer prompt, so a wrong comparison either
 * nags forever or silently hides releases. The parser also has to survive
 * whatever the GitHub API returns, including releases with no APK attached.
 */
class UpdateCheckerTest {

    private fun releaseJson(
        tag: String = "v1.1.0",
        assets: String = """
            {"name":"app-release.apk","size":1966080,
             "browser_download_url":"https://github.com/o/r/releases/download/v1.1.0/app-release.apk"}
        """.trimIndent(),
        body: String = "Fixed a thing",
    ): String = """
        {"tag_name":"$tag","name":"Release $tag","draft":false,
         "body":"$body","assets":[$assets]}
    """.trimIndent()

    // ------------------------------------------------------------- comparison

    @Test
    fun higherVersionIsNewer() {
        assertTrue(UpdateChecker.isNewer("1.1.0", "1.0.0"))
        assertTrue(UpdateChecker.isNewer("2.0.0", "1.9.9"))
        assertTrue(UpdateChecker.isNewer("1.0.1", "1.0.0"))
    }

    @Test
    fun sameOrOlderVersionIsNotNewer() {
        assertFalse(UpdateChecker.isNewer("1.0.0", "1.0.0"))
        assertFalse(UpdateChecker.isNewer("1.0.0", "1.0.1"))
        assertFalse(UpdateChecker.isNewer("0.9.9", "1.0.0"))
    }

    @Test
    fun numericOrderNotLexicographic() {
        // "1.10" sorts before "1.9" as text, but is a later release.
        assertTrue(UpdateChecker.isNewer("1.10.0", "1.9.0"))
        assertFalse(UpdateChecker.isNewer("1.9.0", "1.10.0"))
        assertTrue(UpdateChecker.isNewer("1.0.11", "1.0.9"))
    }

    @Test
    fun missingComponentsCountAsZero() {
        assertTrue(UpdateChecker.isNewer("1.0.1", "1.0"))
        assertFalse(UpdateChecker.isNewer("1.0", "1.0.0"))
        assertTrue(UpdateChecker.isNewer("2", "1.9.9"))
    }

    @Test
    fun leadingVIsIgnored() {
        assertFalse(UpdateChecker.isNewer("v1.0.0", "1.0.0"))
        assertTrue(UpdateChecker.isNewer("v1.0.1", "v1.0.0"))
        assertEquals("1.0.0", UpdateChecker.normalize("  v1.0.0 "))
        assertEquals("1.0.0", UpdateChecker.normalize("V1.0.0"))
    }

    @Test
    fun suffixesDoNotBreakComparison() {
        assertTrue(UpdateChecker.isNewer("1.2.0-beta", "1.1.0"))
        assertFalse(UpdateChecker.isNewer("1.1.0-rc1", "1.1.0"))
    }

    @Test
    fun garbageVersionIsNeverNewer() {
        assertFalse(UpdateChecker.isNewer("", "1.0.0"))
        assertFalse(UpdateChecker.isNewer("beta", "1.0.0"))
    }

    // ----------------------------------------------------------------- parsing

    @Test
    fun parsesTagApkAndNotes() {
        val r = UpdateChecker.parse(releaseJson())
        requireNotNull(r)
        assertEquals("1.1.0", r.version)
        assertTrue(r.apkUrl.endsWith("app-release.apk"))
        assertEquals("Fixed a thing", r.notes)
        assertEquals(1966080L, r.sizeBytes)
    }

    @Test
    fun digestIsTakenFromTheApkAsset() {
        val sha = "ab".repeat(32)
        val json = releaseJson(
            assets = """
                {"name":"notes.txt","size":1,"digest":"sha256:${"00".repeat(32)}",
                 "browser_download_url":"https://github.com/o/r/releases/download/v1.1.0/notes.txt"},
                {"name":"app-release.apk","size":5,"digest":"sha256:${sha.uppercase()}",
                 "browser_download_url":"https://github.com/o/r/releases/download/v1.1.0/app-release.apk"}
            """.trimIndent()
        )
        val r = requireNotNull(UpdateChecker.parse(json))
        assertEquals(sha, r.sha256)
        assertEquals(5L, r.sizeBytes)
    }

    @Test
    fun missingOrMalformedDigestIsNull() {
        assertNull(requireNotNull(UpdateChecker.parse(releaseJson())).sha256)
        val json = releaseJson(
            assets = """{"name":"a.apk","size":1,"digest":"md5:zz",
                "browser_download_url":"https://github.com/o/r/a.apk"}"""
        )
        assertNull(requireNotNull(UpdateChecker.parse(json)).sha256)
    }

    @Test
    fun releaseWithoutApkIsRejected() {
        val json = releaseJson(
            assets = """{"name":"notes.txt","size":10,
                "browser_download_url":"https://github.com/o/r/releases/download/v1.1.0/notes.txt"}"""
        )
        assertNull(UpdateChecker.parse(json))
    }

    @Test
    fun emptyAssetListIsRejected() {
        assertNull(UpdateChecker.parse("""{"tag_name":"v1.1.0","assets":[]}"""))
    }

    @Test
    fun apkIsPickedFromMixedAssets() {
        val json = releaseJson(
            assets = """
                {"name":"checksums.txt","size":100,
                 "browser_download_url":"https://github.com/o/r/releases/download/v1.1.0/checksums.txt"},
                {"name":"app-release.apk","size":2000000,
                 "browser_download_url":"https://github.com/o/r/releases/download/v1.1.0/app-release.apk"}
            """.trimIndent()
        )
        val r = UpdateChecker.parse(json)
        requireNotNull(r)
        assertTrue(r.apkUrl.endsWith(".apk"))
    }

    @Test
    fun nonHttpsAssetIsRejected() {
        val json = releaseJson(
            assets = """{"name":"app.apk","size":10,
                "browser_download_url":"http://evil.example/app.apk"}"""
        )
        assertNull(UpdateChecker.parse(json))
    }

    @Test
    fun malformedJsonReturnsNull() {
        assertNull(UpdateChecker.parse(""))
        assertNull(UpdateChecker.parse("not json at all"))
        assertNull(UpdateChecker.parse("""{"tag_name":"""))
        assertNull(UpdateChecker.parse("""{"message":"Not Found"}"""))
    }

    @Test
    fun escapesInNotesAreDecoded() {
        val json = """
            {"tag_name":"v1.2.0",
             "body":"Line one\nLine two \"quoted\" and \\ backslash",
             "assets":[{"name":"a.apk","size":1,
              "browser_download_url":"https://github.com/o/r/a.apk"}]}
        """.trimIndent()
        val r = UpdateChecker.parse(json)
        requireNotNull(r)
        assertTrue(r.notes.contains("\n"))
        assertTrue(r.notes.contains("\"quoted\""))
        assertTrue(r.notes.contains("\\ backslash"))
    }

    @Test
    fun missingBodyYieldsEmptyNotes() {
        val json = """
            {"tag_name":"v1.2.0","assets":[{"name":"a.apk","size":5,
             "browser_download_url":"https://github.com/o/r/a.apk"}]}
        """.trimIndent()
        val r = UpdateChecker.parse(json)
        requireNotNull(r)
        assertEquals("", r.notes)
    }

    @Test
    fun fieldNameIsNotMatchedInsideValues() {
        // A body mentioning tag_name must not be read as the tag itself.
        val json = """
            {"body":"see tag_name below","tag_name":"v3.0.0",
             "assets":[{"name":"a.apk","size":1,
              "browser_download_url":"https://github.com/o/r/a.apk"}]}
        """.trimIndent()
        val r = UpdateChecker.parse(json)
        requireNotNull(r)
        assertEquals("3.0.0", r.version)
    }
}
