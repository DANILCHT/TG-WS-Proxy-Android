package com.flowseal.tgwsproxy.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.flowseal.tgwsproxy.R
import com.flowseal.tgwsproxy.core.Const
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.NetworkBinder
import com.flowseal.tgwsproxy.core.ProxyEngine
import com.flowseal.tgwsproxy.core.Settings
import com.flowseal.tgwsproxy.core.Stats
import com.flowseal.tgwsproxy.core.UpdateManager
import com.flowseal.tgwsproxy.ui.MainActivity
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service that owns the [ProxyEngine].
 *
 * The proxy only listens on a local socket; it does not capture other apps'
 * traffic, so no VpnService and no extra permission prompt is needed. Telegram
 * connects to it as a normal MTProto proxy at 127.0.0.1:<port>.
 *
 * Security note: the listener is unauthenticated in the sense that anyone able
 * to reach the port can use it as a proxy — access is gated only by the MTProto
 * secret. With the default host 127.0.0.1 only apps on this device can connect.
 * Setting host to 0.0.0.0 exposes it to the whole local network.
 */
class ProxyService : Service() {

    companion object {
        const val ACTION_START = "com.flowseal.tgwsproxy.START"
        const val ACTION_STOP = "com.flowseal.tgwsproxy.STOP"
        const val ACTION_RESTART = "com.flowseal.tgwsproxy.RESTART"

        const val BROADCAST_STATE = "com.flowseal.tgwsproxy.STATE"
        const val EXTRA_RUNNING = "running"
        const val EXTRA_ERROR = "error"

        private const val CHANNEL_ID = "proxy_status"
        private const val CHANNEL_ID_QUIET = "proxy_status_quiet"
        private const val NOTIFICATION_ID = 1001
        private const val STATS_UPDATE_INTERVAL_MS = 5_000L
        private const val UPDATE_POLL_MS = 30 * 60 * 1000L
        private const val UPDATE_FIRST_DELAY_MS = 2 * 60 * 1000L

        @Volatile
        private var engineRef: ProxyEngine? = null

        val isRunning: Boolean
            get() = engineRef?.isRunning == true

        fun engine(): ProxyEngine? = engineRef

        fun start(context: Context) {
            val intent = Intent(context, ProxyService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, ProxyService::class.java).setAction(ACTION_STOP)
            )
        }

        fun restart(context: Context) {
            val intent = Intent(context, ProxyService::class.java).setAction(ACTION_RESTART)
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    private val starting = AtomicBoolean(false)
    private var engine: ProxyEngine? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var statsThread: Thread? = null
    private var updateThread: Thread? = null

    @Volatile
    private var statsRunning = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        NetworkBinder.init(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // Only an explicit stop clears it; a killed process comes back.
                Settings.get(this).wasRunning = false
                stopProxy()
                stopSelf()
                return START_NOT_STICKY
            }

            ACTION_RESTART -> {
                stopProxy()
                startProxy()
            }

            else -> startProxy()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    // ------------------------------------------------------------------ proxy

    private fun startProxy() {
        if (!starting.compareAndSet(false, true)) return
        try {
            if (engine?.isRunning == true) {
                startForeground(NOTIFICATION_ID, buildNotification(true, null))
                return
            }

            val settings = Settings.get(this)
            Logger.verbose = settings.verbose

            val validationError = settings.validate()
            if (validationError != null) {
                Logger.e("Invalid configuration: $validationError")
                broadcastState(false, validationError)
                stopSelf()
                return
            }

            startForeground(NOTIFICATION_ID, buildNotification(false, null))

            val cfg = settings.toProxyConfig()
            val e = ProxyEngine(cfg)
            try {
                e.start()
            } catch (ex: Exception) {
                val msg = when (ex) {
                    is java.net.BindException ->
                        "Port ${cfg.port} is already in use or not permitted"
                    else -> ex.message ?: ex.javaClass.simpleName
                }
                Logger.e("Failed to start proxy: $msg", ex)
                broadcastState(false, msg)
                stopForegroundCompat()
                stopSelf()
                return
            }

            engine = e
            engineRef = e
            settings.wasRunning = true
            acquireLocks()
            startStatsUpdates()
            startUpdatePolling()
            updateNotification(true, null)
            broadcastState(true, null)
        } finally {
            starting.set(false)
        }
    }

    private fun stopProxy() {
        statsRunning = false
        statsThread?.interrupt()
        statsThread = null
        updateThread?.interrupt()
        updateThread = null
        engine?.stop()
        engine = null
        engineRef = null
        releaseLocks()
        broadcastState(false, null)
        stopForegroundCompat()
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(Service.STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    // ------------------------------------------------------------------ locks

    // No wakelock timeout on purpose: the lock's lifetime is the foreground
    // service's lifetime, and it is released in releaseLocks() on shutdown.
    @android.annotation.SuppressLint("WakelockTimeout")
    private fun acquireLocks() {
        runCatching {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            val wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TgWsProxy:proxy")
            wl.setReferenceCounted(false)
            wl.acquire()
            wakeLock = wl
        }
        runCatching {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            val wfl = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "TgWsProxy:wifi")
            wfl.setReferenceCounted(false)
            wfl.acquire()
            wifiLock = wfl
        }
    }

    private fun releaseLocks() {
        runCatching { wakeLock?.takeIf { it.isHeld }?.release() }
        runCatching { wifiLock?.takeIf { it.isHeld }?.release() }
        wakeLock = null
        wifiLock = null
    }

    // ----------------------------------------------------------- notification

    /**
     * Android requires a visible notification for a foreground service, so the
     * quiet mode uses a separate IMPORTANCE_MIN channel instead: no traffic
     * updates, no action button, collapsed in the shade and hidden from the
     * lock screen. That is as close to "off" as the platform allows.
     */
    private fun channelId(): String =
        if (Settings.get(this).quietNotification) CHANNEL_ID_QUIET else CHANNEL_ID

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = getSystemService(NotificationManager::class.java)

        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
            channel.description = getString(R.string.notif_channel_desc)
            channel.setShowBadge(false)
            nm.createNotificationChannel(channel)
        }

        if (nm.getNotificationChannel(CHANNEL_ID_QUIET) == null) {
            val quiet = NotificationChannel(
                CHANNEL_ID_QUIET,
                getString(R.string.notif_channel_quiet_name),
                NotificationManager.IMPORTANCE_MIN,
            )
            quiet.description = getString(R.string.notif_channel_quiet_desc)
            quiet.setShowBadge(false)
            quiet.enableVibration(false)
            quiet.setSound(null, null)
            quiet.lockscreenVisibility = Notification.VISIBILITY_SECRET
            nm.createNotificationChannel(quiet)
        }
    }

    private fun buildNotification(running: Boolean, detail: String?): Notification {
        val settings = Settings.get(this)
        val quiet = settings.quietNotification
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            pendingFlags(),
        )

        val title = if (running) {
            if (quiet) {
                getString(R.string.notif_running_quiet)
            } else {
                getString(R.string.notif_running, settings.host, settings.port)
            }
        } else {
            getString(R.string.notif_starting)
        }

        val builder = NotificationCompat.Builder(this, channelId())
            .setSmallIcon(R.drawable.ic_stat_proxy)
            .setContentTitle(title)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openIntent)

        if (quiet) {
            return builder
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                .build()
        }

        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, ProxyService::class.java).setAction(ACTION_STOP),
            pendingFlags(),
        )
        val text = detail ?: if (running) {
            getString(
                R.string.notif_traffic,
                Const.humanBytes(Stats.bytesUp.get()),
                Const.humanBytes(Stats.bytesDown.get()),
                Stats.connectionsActive.get(),
            )
        } else {
            getString(R.string.notif_channel_desc)
        }

        return builder
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(0, getString(R.string.action_stop), stopIntent)
            .build()
    }

    private fun pendingFlags(): Int =
        if (Build.VERSION.SDK_INT >= 23) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }

    private fun updateNotification(running: Boolean, detail: String?) {
        runCatching {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify(NOTIFICATION_ID, buildNotification(running, detail))
        }
    }

    private fun startStatsUpdates() {
        // In quiet mode the notification carries no traffic counters, so there
        // is nothing to refresh.
        if (Settings.get(this).quietNotification) return
        statsRunning = true
        val t = Thread({
            while (statsRunning) {
                try {
                    Thread.sleep(STATS_UPDATE_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                if (!statsRunning) return@Thread
                updateNotification(engine?.isRunning == true, null)
            }
        }, "notif-stats")
        t.isDaemon = true
        statsThread = t
        t.start()
    }

    /**
     * While the proxy runs the process is alive anyway, so it doubles as the
     * update scheduler (JobScheduler may defer jobs for a long time on some
     * ROMs). The real rate limit is in [UpdateManager.runScheduled].
     */
    private fun startUpdatePolling() {
        UpdateJobService.schedule(this)
        val ctx = applicationContext
        val t = Thread({
            var delay = UPDATE_FIRST_DELAY_MS
            while (true) {
                try {
                    Thread.sleep(delay)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                delay = UPDATE_POLL_MS
                runCatching { UpdateManager.runScheduled(ctx) }
                    .onFailure { Logger.d("Update poll failed: $it") }
            }
        }, "update-poll")
        t.isDaemon = true
        updateThread = t
        t.start()
    }

    private fun broadcastState(running: Boolean, error: String?) {
        val intent = Intent(BROADCAST_STATE)
            .setPackage(packageName)
            .putExtra(EXTRA_RUNNING, running)
            .putExtra(EXTRA_ERROR, error)
        sendBroadcast(intent)
    }
}
