package com.flowseal.tgwsproxy.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import java.io.File

/**
 * Downloads a release APK and hands it to the system installer.
 *
 * The app cannot install updates silently — Android always shows its own
 * confirmation screen, and that is intentional. Everything here just gets the
 * file into place and opens that screen.
 */
object UpdateInstaller {

    private const val FILE_NAME = "update.apk"
    private const val TIMEOUT_MS = 30_000
    private const val MAX_APK_BYTES = 100L * 1024 * 1024

    /** Downloads [url] into cache, reporting 0..100 through [onProgress]. */
    @Throws(Exception::class)
    fun download(
        context: Context,
        url: String,
        expectedSize: Long,
        onProgress: (Int) -> Unit,
    ): File {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        val target = File(dir, FILE_NAME)
        if (target.exists()) target.delete()

        val conn = NetworkBinder.openConnection(java.net.URL(url))
                as java.net.HttpURLConnection
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "tg-ws-proxy-android")

        try {
            if (conn.responseCode !in 200..299) {
                throw java.io.IOException("HTTP ${conn.responseCode}")
            }
            val total = if (expectedSize > 0) expectedSize else conn.contentLength.toLong()
            if (total > MAX_APK_BYTES) {
                throw java.io.IOException("APK too large: $total bytes")
            }

            var written = 0L
            var lastPercent = -1
            conn.inputStream.use { input ->
                target.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        out.write(buf, 0, n)
                        written += n
                        if (written > MAX_APK_BYTES) {
                            throw java.io.IOException("APK exceeded size limit")
                        }
                        if (total > 0) {
                            val percent = ((written * 100) / total).toInt().coerceIn(0, 100)
                            if (percent != lastPercent) {
                                lastPercent = percent
                                onProgress(percent)
                            }
                        }
                    }
                }
            }
            Logger.i("Update downloaded: ${Const.humanBytes(written)}")
            return target
        } catch (e: Throwable) {
            runCatching { target.delete() }
            throw e
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Opens the system installer for [apk]. Returns false when the OS has not
     * granted the install-packages permission yet; call [openInstallPermission]
     * in that case.
     */
    fun install(context: Context, apk: File): Boolean {
        if (Build.VERSION.SDK_INT >= 26 &&
            !context.packageManager.canRequestPackageInstalls()
        ) {
            return false
        }

        val uri: Uri = FileProvider.getUriForFile(
            context, "${context.packageName}.updates", apk,
        )
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
        return true
    }

    /** Sends the user to the "install unknown apps" screen for this app. */
    fun openInstallPermission(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        runCatching {
            context.startActivity(
                Intent(
                    android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}"),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
    }

    fun clearCache(context: Context) {
        runCatching { File(File(context.cacheDir, "updates"), FILE_NAME).delete() }
    }
}
