package com.flowseal.tgwsproxy.core

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.flowseal.tgwsproxy.R
import com.flowseal.tgwsproxy.ui.MainActivity
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Background update flow: check GitHub on a schedule and, when the user left
 * automatic installation on, download, verify and install without asking.
 *
 * Triggered by [com.flowseal.tgwsproxy.service.UpdateJobService] (periodic
 * job), by the running proxy service and when the app is opened.
 */
object UpdateManager {

    /** Background checks are spaced at least this far apart. */
    const val CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000L

    const val EXTRA_SHOW_UPDATE = "show_update"

    private const val CHANNEL_ID = "updates"
    private const val NOTIFICATION_ID = 1002

    private val busy = AtomicBoolean(false)

    fun appVersion(context: Context): String = runCatching {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "?"
    }.getOrDefault("?")

    /**
     * Runs one scheduled check on the calling (background) thread. Honours the
     * settings, the rate limit and a skipped version; [force] skips the rate
     * limit only.
     */
    fun runScheduled(context: Context, force: Boolean = false) {
        val s = Settings.get(context)
        if (!s.autoUpdateCheck) return
        val now = System.currentTimeMillis()
        if (!force && now - s.lastUpdateCheck < CHECK_INTERVAL_MS) return
        if (!busy.compareAndSet(false, true)) return
        try {
            s.lastUpdateCheck = now
            val current = appVersion(context)
            val release = UpdateChecker.check(current) ?: return
            if (UpdateChecker.normalize(release.version) == s.skippedUpdate) return
            Logger.i("Update available: ${release.version} (installed $current)")

            if (s.autoInstallUpdates) {
                try {
                    installRelease(context, release)
                } catch (e: Exception) {
                    Logger.w("Automatic update to ${release.version} failed: $e")
                    notifyAvailable(context, release.version)
                }
            } else {
                notifyAvailable(context, release.version)
            }
        } finally {
            busy.set(false)
        }
    }

    /** Download, verify, install. Blocking; call off the main thread. */
    @Throws(Exception::class)
    fun installRelease(context: Context, release: UpdateChecker.Release, onProgress: (Int) -> Unit = {}) {
        val apk = UpdateInstaller.download(context, release, onProgress)
        try {
            UpdateInstaller.verify(context, apk)
        } catch (e: Exception) {
            UpdateInstaller.clearCache(context)
            throw e
        }
        UpdateInstaller.install(context, apk, release.version)
    }

    // ------------------------------------------------------------ notifications

    private fun channel(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = context.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val ch = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notif_channel_updates),
            NotificationManager.IMPORTANCE_DEFAULT,
        )
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }

    private fun post(context: Context, title: String, text: String, intent: PendingIntent) {
        runCatching {
            channel(context)
            val n = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_stat_proxy)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setAutoCancel(true)
                .setContentIntent(intent)
                .build()
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify(NOTIFICATION_ID, n)
        }
    }

    private fun immutable(): Int =
        PendingIntent.FLAG_UPDATE_CURRENT or
            if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0

    /** "Version X is available" — opens the app, which shows the update dialog. */
    fun notifyAvailable(context: Context, version: String) {
        val open = Intent(context, MainActivity::class.java)
            .putExtra(EXTRA_SHOW_UPDATE, true)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        post(
            context,
            context.getString(R.string.update_title, version),
            context.getString(R.string.update_notif_available),
            PendingIntent.getActivity(context, 10, open, immutable()),
        )
    }

    /** The system wants a confirmation: the notification opens its dialog. */
    fun notifyNeedsConfirmation(context: Context, version: String, confirm: Intent) {
        post(
            context,
            context.getString(R.string.update_title, version),
            context.getString(R.string.update_notif_confirm),
            PendingIntent.getActivity(
                context, 11, confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), immutable(),
            ),
        )
    }

    fun notifyFailed(context: Context, version: String, message: String) {
        val open = Intent(context, MainActivity::class.java)
            .putExtra(EXTRA_SHOW_UPDATE, true)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        post(
            context,
            context.getString(R.string.update_notif_failed_title, version),
            message,
            PendingIntent.getActivity(context, 12, open, immutable()),
        )
    }

    fun cancelNotification(context: Context) {
        runCatching {
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .cancel(NOTIFICATION_ID)
        }
    }
}
