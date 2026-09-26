package com.flowseal.tgwsproxy.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.Settings
import com.flowseal.tgwsproxy.core.UpdateInstaller

/**
 * Starts the proxy after a reboot when the user enabled autostart, and brings
 * it back after the app updated itself (the update kills the old process).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val settings = Settings.get(context)
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> {
                UpdateJobService.schedule(context)
                if (!settings.autostart) return
                Logger.i("Boot completed, autostarting proxy")
                ProxyService.start(context)
            }

            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                UpdateInstaller.clearCache(context)
                UpdateJobService.schedule(context)
                if (!settings.wasRunning) return
                Logger.i("App updated, restarting proxy")
                ProxyService.start(context)
            }
        }
    }
}
