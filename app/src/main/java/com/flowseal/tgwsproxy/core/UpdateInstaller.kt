package com.flowseal.tgwsproxy.core

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.flowseal.tgwsproxy.net.HttpLite
import com.flowseal.tgwsproxy.service.UpdateReceiver
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * Downloads a release APK, checks it and installs it through PackageInstaller.
 *
 * On Android 12+ an app may update *itself* without a confirmation screen
 * (setRequireUserAction + UPDATE_PACKAGES_WITHOUT_USER_ACTION). Older systems,
 * or the first update after a manual install on some ROMs, still show the
 * system dialog; the session result then carries the intent to open it, see
 * [UpdateReceiver].
 *
 * Before anything reaches the installer the file must match the SHA-256 that
 * GitHub publishes for the asset, carry this app's package name and a higher
 * versionCode, and be signed with the same certificate as the running app.
 */
object UpdateInstaller {

    private const val FILE_NAME = "update.apk"
    private const val TIMEOUT_MS = 30_000
    private const val MAX_APK_BYTES = 100L * 1024 * 1024

    class VerificationError(msg: String) : IOException(msg)

    /** Downloads [release] into cache, reporting 0..100 through [onProgress]. */
    @Throws(Exception::class)
    fun download(
        context: Context,
        release: UpdateChecker.Release,
        onProgress: (Int) -> Unit = {},
    ): File {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        val target = File(dir, FILE_NAME)
        if (target.exists()) target.delete()

        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val written = HttpLite.stream(
                HttpLite.Request(url = release.apkUrl, timeoutMs = TIMEOUT_MS)
            ) { status, _, body, length, _ ->
                if (status !in 200..299) throw IOException("HTTP $status")
                val total = if (release.sizeBytes > 0) release.sizeBytes else length
                if (total > MAX_APK_BYTES) throw IOException("APK too large: $total bytes")

                var written = 0L
                var lastPercent = -1
                target.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = body.read(buf)
                        if (n <= 0) break
                        out.write(buf, 0, n)
                        digest.update(buf, 0, n)
                        written += n
                        if (written > MAX_APK_BYTES) throw IOException("APK exceeded size limit")
                        if (total > 0) {
                            val percent = ((written * 100) / total).toInt().coerceIn(0, 100)
                            if (percent != lastPercent) {
                                lastPercent = percent
                                onProgress(percent)
                            }
                        }
                    }
                }
                written
            }

            if (release.sizeBytes > 0 && written != release.sizeBytes) {
                throw VerificationError("size mismatch: got $written, expected ${release.sizeBytes}")
            }
            val actual = Const.toHex(digest.digest())
            if (release.sha256 != null && actual != release.sha256) {
                throw VerificationError("SHA-256 mismatch")
            }
            Logger.i(
                "Update downloaded: ${Const.humanBytes(written)}" +
                    if (release.sha256 != null) ", SHA-256 verified" else ""
            )
            return target
        } catch (e: Throwable) {
            runCatching { target.delete() }
            throw e
        }
    }

    /**
     * Checks package name, version and signing certificate of [apk] against
     * the installed app. Throws [VerificationError] on mismatch.
     */
    @Suppress("DEPRECATION")
    @SuppressLint("PackageManagerGetSignatures")
    fun verify(context: Context, apk: File) {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= 28) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val archive = pm.getPackageArchiveInfo(apk.path, flags)
            ?: throw VerificationError("not a valid APK")
        if (archive.packageName != context.packageName) {
            throw VerificationError("package ${archive.packageName} is not ${context.packageName}")
        }
        val installed = pm.getPackageInfo(context.packageName, flags)
        if (versionCode(archive) <= versionCode(installed)) {
            throw VerificationError("version ${archive.versionName} is not newer")
        }

        val mine = certDigests(installed)
        var theirs = certDigests(archive)
        if (theirs.isEmpty() && Build.VERSION.SDK_INT >= 28) {
            // Some releases only fill the legacy field for archives.
            theirs = certDigests(pm.getPackageArchiveInfo(apk.path, PackageManager.GET_SIGNATURES))
        }
        if (theirs.isEmpty()) {
            // The installer will enforce the signature anyway; just note it.
            Logger.w("Update: could not read APK signature, relying on the system check")
            return
        }
        if (mine.intersect(theirs).isEmpty()) {
            throw VerificationError("APK is signed with a different key")
        }
    }

    @Suppress("DEPRECATION")
    private fun versionCode(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()

    @Suppress("DEPRECATION")
    private fun certDigests(info: PackageInfo?): Set<String> {
        if (info == null) return emptySet()
        val sigs = if (Build.VERSION.SDK_INT >= 28) {
            val si = info.signingInfo
            when {
                si == null -> info.signatures
                si.hasMultipleSigners() -> si.apkContentsSigners
                else -> si.signingCertificateHistory
            }
        } else {
            info.signatures
        } ?: return emptySet()
        val md = MessageDigest.getInstance("SHA-256")
        return sigs.map { Const.toHex(md.digest(it.toByteArray())) }.toSet()
    }

    /**
     * Commits [apk] to a PackageInstaller session. The outcome arrives in
     * [UpdateReceiver]; on success the process is replaced and restarted.
     */
    @Throws(Exception::class)
    fun install(context: Context, apk: File, version: String) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(context.packageName)
        params.setSize(apk.length())
        if (Build.VERSION.SDK_INT >= 31) {
            params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        if (Build.VERSION.SDK_INT >= 26) {
            params.setInstallReason(PackageManager.INSTALL_REASON_USER)
        }
        if (Build.VERSION.SDK_INT >= 34) {
            params.setPackageSource(PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE)
        }

        val sessionId = installer.createSession(params)
        val session = installer.openSession(sessionId)
        try {
            session.openWrite("base.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out, 64 * 1024) }
                session.fsync(out)
            }
            val intent = Intent(context, UpdateReceiver::class.java)
                .setAction(UpdateReceiver.ACTION_INSTALL_STATUS)
                .putExtra(UpdateReceiver.EXTRA_VERSION, version)
            // The system fills in the status extras, so the intent must be mutable.
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
            val pi = PendingIntent.getBroadcast(context, sessionId, intent, flags)
            Logger.i("Installing update $version")
            session.commit(pi.intentSender)
        } catch (e: Throwable) {
            runCatching { session.abandon() }
            throw e
        } finally {
            runCatching { session.close() }
        }
    }

    fun canInstall(context: Context): Boolean =
        Build.VERSION.SDK_INT < 26 || context.packageManager.canRequestPackageInstalls()

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
