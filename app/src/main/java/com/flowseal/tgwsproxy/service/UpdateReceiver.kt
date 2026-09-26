package com.flowseal.tgwsproxy.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.UpdateInstaller
import com.flowseal.tgwsproxy.core.UpdateManager

/** Result of a PackageInstaller session started by [UpdateInstaller.install]. */
class UpdateReceiver : BroadcastReceiver() {

    companion object {
        const val ACTION_INSTALL_STATUS = "com.flowseal.tgwsproxy.INSTALL_STATUS"
        const val EXTRA_VERSION = "version"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_INSTALL_STATUS) return
        val version = intent.getStringExtra(EXTRA_VERSION) ?: "?"
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)

        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                } ?: return
                Logger.i("Update $version needs confirmation")
                // Works while the app is in front; otherwise the system blocks
                // background activity starts and the notification is the way in.
                runCatching { context.startActivity(Intent(confirm).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                UpdateManager.notifyNeedsConfirmation(context, version, confirm)
            }

            PackageInstaller.STATUS_SUCCESS -> {
                Logger.i("Update $version installed")
                UpdateManager.cancelNotification(context)
                UpdateInstaller.clearCache(context)
            }

            PackageInstaller.STATUS_FAILURE_ABORTED -> Logger.i("Update $version cancelled")

            else -> {
                Logger.w("Update $version failed: status=$status ${message.orEmpty()}")
                UpdateInstaller.clearCache(context)
                UpdateManager.notifyFailed(context, version, message ?: "status $status")
            }
        }
    }
}
