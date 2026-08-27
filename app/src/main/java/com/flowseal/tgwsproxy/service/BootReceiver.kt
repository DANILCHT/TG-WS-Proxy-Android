package com.flowseal.tgwsproxy.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.Settings

/** Starts the proxy after a reboot when the user enabled autostart. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Settings.get(context).autostart) return
        Logger.i("Boot completed, autostarting proxy")
        ProxyService.start(context)
    }
}
