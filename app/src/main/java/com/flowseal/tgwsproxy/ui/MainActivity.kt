package com.flowseal.tgwsproxy.ui

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.MenuItem
import android.view.View
import android.widget.ImageView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.snackbar.Snackbar
import com.flowseal.tgwsproxy.R
import com.flowseal.tgwsproxy.core.Const
import com.flowseal.tgwsproxy.core.Diagnostics
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.ProxyConfig
import com.flowseal.tgwsproxy.core.Settings
import com.flowseal.tgwsproxy.core.Stats
import com.flowseal.tgwsproxy.core.UpdateChecker
import com.flowseal.tgwsproxy.core.UpdateInstaller
import com.flowseal.tgwsproxy.core.UpdateManager
import com.flowseal.tgwsproxy.databinding.ActivityMainBinding
import com.flowseal.tgwsproxy.service.ProxyService
import com.flowseal.tgwsproxy.service.UpdateJobService

class MainActivity : AppCompatActivity() {

    companion object {
        const val RELAY_GUIDE_URL =
            "https://github.com/DANILCHT/TG-WS-Proxy-Android/blob/main/relay/README.md"
    }

    private lateinit var binding: ActivityMainBinding
    private lateinit var settings: Settings

    private val handler = Handler(Looper.getMainLooper())
    private var logListener: ((String) -> Unit)? = null

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val error = intent?.getStringExtra(ProxyService.EXTRA_ERROR)
            refreshStatus()
            if (error != null) toast(error)
        }
    }

    private val uiTicker = object : Runnable {
        override fun run() {
            refreshStatus()
            refreshStats()
            handler.postDelayed(this, 2_000)
        }
    }

    private val notifPermissionLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) toast(getString(R.string.msg_notif_permission))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        settings = Settings.get(this)
        Logger.verbose = settings.verbose
        com.flowseal.tgwsproxy.core.NetworkBinder.init(this)

        loadSettingsIntoForm()
        wireUp()
        requestNotificationPermission()
        maybeShowFirstRun()
        UpdateJobService.schedule(this)
        if (intent?.getBooleanExtra(UpdateManager.EXTRA_SHOW_UPDATE, false) == true) {
            checkForUpdateNow()
        } else {
            maybeCheckForUpdate()
        }

        binding.toolbar.setOnMenuItemClickListener { onMenuItem(it) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(UpdateManager.EXTRA_SHOW_UPDATE, false)) checkForUpdateNow()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(ProxyService.BROADCAST_STATE)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(stateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(stateReceiver, filter)
        }

        renderLogs(Logger.snapshot())
        val l: (String) -> Unit = { line ->
            handler.post { appendLogLine(line) }
        }
        logListener = l
        Logger.addListener(l)

        handler.post(uiTicker)
    }

    override fun onStop() {
        super.onStop()
        runCatching { unregisterReceiver(stateReceiver) }
        logListener?.let { Logger.removeListener(it) }
        logListener = null
        handler.removeCallbacks(uiTicker)
    }

    // ------------------------------------------------------------------- wiring

    private fun wireUp() = with(binding) {
        toggleButton.setOnClickListener {
            if (ProxyService.isRunning) {
                ProxyService.stop(this@MainActivity)
            } else {
                val error = saveSettings(silent = true)
                if (error != null) {
                    toast(error)
                    return@setOnClickListener
                }
                ProxyService.start(this@MainActivity)
            }
            handler.postDelayed({ refreshStatus() }, 600)
        }

        openTelegramButton.setOnClickListener { openInTelegram() }
        copyLinkButton.setOnClickListener {
            copyToClipboard(tgLink())
            toast(getString(R.string.msg_copied))
        }
        diagnoseButton.setOnClickListener { runDiagnostics() }

        regenerateSecretButton.setOnClickListener {
            secretInput.setText(settings.regenerateSecret())
            toast(getString(R.string.msg_secret_regenerated))
        }

        saveButton.setOnClickListener {
            val error = saveSettings(silent = false)
            if (error != null) {
                toast(error)
                return@setOnClickListener
            }
            if (ProxyService.isRunning) {
                ProxyService.restart(this@MainActivity)
                toast(getString(R.string.msg_saved_restart))
            } else {
                toast(getString(R.string.msg_saved))
            }
            refreshStatus()
        }

        // Collapsible sections: everything starts folded so the first screen is
        // just the status card and the section list.
        section(evasionHeader, evasionContent, evasionChevron)
        section(relayHeader, relayContent, relayChevron)
        section(connectionHeader, connectionContent, connectionChevron)
        section(maskingHeader, maskingContent, maskingChevron)
        section(fallbackHeader, fallbackContent, fallbackChevron)
        section(advancedHeader, advancedContent, advancedChevron)
        section(appHeader, appContent, appChevron)
        section(logsHeader, logsContent, logsChevron)

        // The channel changes with this switch, so a running service needs to
        // re-issue its notification for the new look to take effect.
        quietNotificationSwitch.setOnCheckedChangeListener { _, checked ->
            settings.quietNotification = checked
            if (ProxyService.isRunning) ProxyService.restart(this@MainActivity)
        }
        notificationSettingsButton.setOnClickListener { openNotificationSettings() }

        autoUpdateSwitch.setOnCheckedChangeListener { _, checked ->
            settings.autoUpdateCheck = checked
            if (checked) settings.skippedUpdate = ""
            autoInstallSwitch.isEnabled = checked
            UpdateJobService.schedule(this@MainActivity)
        }
        autoInstallSwitch.setOnCheckedChangeListener { _, checked ->
            settings.autoInstallUpdates = checked
        }
        relayGuideButton.setOnClickListener { openUrl(RELAY_GUIDE_URL) }
        checkUpdateButton.setOnClickListener { checkForUpdateNow() }

        tlsSplitSwitch.setOnCheckedChangeListener { _, checked ->
            tlsSplitDelayLayout.isEnabled = checked
            tlsSplitDelayInput.isEnabled = checked
        }

        cfUserSwitch.setOnCheckedChangeListener { _, checked ->
            cfUserDomainLayout.isEnabled = checked
            cfUserDomainInput.isEnabled = checked
        }
        cfWorkerSwitch.setOnCheckedChangeListener { _, checked ->
            cfWorkerDomainLayout.isEnabled = checked
            cfWorkerDomainInput.isEnabled = checked
        }

        copyLogsButton.setOnClickListener {
            copyToClipboard(Logger.snapshot().joinToString("\n"))
            toast(getString(R.string.msg_copied))
        }
        clearLogsButton.setOnClickListener {
            Logger.clear()
            logText.text = ""
            toast(getString(R.string.msg_logs_cleared))
        }
    }

    /** Makes [header] toggle [content] and rotates [chevron] to match. */
    private fun section(header: View, content: View, chevron: ImageView) {
        chevron.rotation = if (content.visibility == View.VISIBLE) 180f else 0f
        header.setOnClickListener {
            val show = content.visibility != View.VISIBLE
            content.visibility = if (show) View.VISIBLE else View.GONE
            chevron.animate().rotation(if (show) 180f else 0f).setDuration(150).start()
        }
    }

    private fun onMenuItem(item: MenuItem): Boolean = when (item.itemId) {
        R.id.action_restart -> {
            if (ProxyService.isRunning) ProxyService.restart(this) else ProxyService.start(this)
            handler.postDelayed({ refreshStatus() }, 600)
            true
        }

        R.id.action_check_update -> {
            checkForUpdateNow()
            true
        }

        R.id.action_about -> {
            AlertDialog.Builder(this)
                .setTitle(R.string.about_title)
                .setMessage(R.string.about_body)
                .setPositiveButton(R.string.about_close, null)
                .setNeutralButton(R.string.action_open_releases) { _, _ -> openReleasesPage() }
                .show()
            true
        }

        else -> false
    }

    // ----------------------------------------------------------------- settings

    private fun loadSettingsIntoForm() = with(binding) {
        hostInput.setText(settings.host)
        portInput.setText(settings.port.toString())
        secretInput.setText(settings.secret)
        dcIpInput.setText(settings.dcIp.joinToString(", "))
        relaysInput.setText(settings.relays.joinToString("\n"))
        relayFirstSwitch.isChecked = settings.relayFirst
        noSecureSwitch.isChecked = settings.noSecure
        verifyTlsSwitch.isChecked = settings.verifyTls
        fakeTlsInput.setText(settings.fakeTlsDomain)
        tlsSplitSwitch.isChecked = settings.tlsSplit
        tlsSplitDelayInput.setText(settings.tlsSplitDelayMs.toString())
        tlsSplitDelayLayout.isEnabled = settings.tlsSplit
        tlsSplitDelayInput.isEnabled = settings.tlsSplit
        frontingFirstSwitch.isChecked = settings.frontingFirst
        frontingSniInput.setText(settings.frontingSni)
        bypassVpnSwitch.isChecked = settings.bypassVpn
        mobileEvasionSwitch.isChecked = settings.mobileEvasion
        cfproxySwitch.isChecked = settings.cfproxy
        cfUserSwitch.isChecked = settings.cfUserDomainEnabled
        cfUserDomainInput.setText(settings.cfUserDomain.joinToString(", "))
        cfUserDomainLayout.isEnabled = settings.cfUserDomainEnabled
        cfUserDomainInput.isEnabled = settings.cfUserDomainEnabled
        cfWorkerSwitch.isChecked = settings.cfWorkerEnabled
        cfWorkerDomainInput.setText(settings.cfWorkerDomain.joinToString(", "))
        cfWorkerDomainLayout.isEnabled = settings.cfWorkerEnabled
        cfWorkerDomainInput.isEnabled = settings.cfWorkerEnabled
        poolSizeInput.setText(settings.poolSize.toString())
        bufKbInput.setText(settings.bufKb.toString())
        forceTestDcSwitch.isChecked = settings.forceTestDc
        autostartSwitch.isChecked = settings.autostart
        verboseSwitch.isChecked = settings.verbose
        quietNotificationSwitch.isChecked = settings.quietNotification
        autoUpdateSwitch.isChecked = settings.autoUpdateCheck
        autoInstallSwitch.isChecked = settings.autoInstallUpdates
        autoInstallSwitch.isEnabled = settings.autoUpdateCheck
        versionText.text = getString(R.string.version_current, appVersion())
    }

    /** Persists the form. Returns an error message, or null on success. */
    private fun saveSettings(silent: Boolean): String? = with(binding) {
        val port = portInput.text.toString().trim().toIntOrNull()
            ?: return "Port must be a number between 1 and 65535"
        val poolSize = poolSizeInput.text.toString().trim().toIntOrNull()
            ?: return "Pool size must be a number"
        val bufKb = bufKbInput.text.toString().trim().toIntOrNull()
            ?: return "Buffer size must be a number"
        val splitDelay = tlsSplitDelayInput.text.toString().trim().ifEmpty { "0" }.toIntOrNull()
            ?: return "TLS split delay must be a number"

        settings.host = hostInput.text.toString().trim()
        settings.port = port
        settings.secret = secretInput.text.toString().trim().lowercase()
        settings.dcIp = splitInput(dcIpInput.text.toString())
        settings.relays = relaysInput.text.toString().split('\n', ',', ' ', ';')
            .map { it.trim() }.filter { it.isNotEmpty() }
        settings.relayFirst = relayFirstSwitch.isChecked
        settings.noSecure = noSecureSwitch.isChecked
        settings.verifyTls = verifyTlsSwitch.isChecked
        settings.fakeTlsDomain = fakeTlsInput.text.toString().trim()
        settings.tlsSplit = tlsSplitSwitch.isChecked
        settings.tlsSplitDelayMs = splitDelay
        settings.frontingFirst = frontingFirstSwitch.isChecked
        settings.frontingSni = frontingSniInput.text.toString().trim()
        settings.bypassVpn = bypassVpnSwitch.isChecked
        settings.mobileEvasion = mobileEvasionSwitch.isChecked
        settings.cfproxy = cfproxySwitch.isChecked
        settings.cfUserDomainEnabled = cfUserSwitch.isChecked
        settings.cfUserDomain = splitInput(cfUserDomainInput.text.toString())
        settings.cfWorkerEnabled = cfWorkerSwitch.isChecked
        settings.cfWorkerDomain = splitInput(cfWorkerDomainInput.text.toString())
        settings.poolSize = poolSize
        settings.bufKb = bufKb
        settings.forceTestDc = forceTestDcSwitch.isChecked
        settings.autostart = autostartSwitch.isChecked
        settings.verbose = verboseSwitch.isChecked
        settings.quietNotification = quietNotificationSwitch.isChecked
        settings.autoUpdateCheck = autoUpdateSwitch.isChecked
        settings.autoInstallUpdates = autoInstallSwitch.isChecked
        Logger.verbose = settings.verbose

        val validation = settings.validate()
        if (validation != null) return validation

        if (!silent) loadSettingsIntoForm()
        return null
    }

    private fun splitInput(raw: String): List<String> =
        raw.split(',', ';', '\n', ' ')
            .map { it.trim() }
            .filter { it.isNotEmpty() }

    // -------------------------------------------------------------------- state

    private fun refreshStatus() {
        val running = ProxyService.isRunning
        binding.statusText.text = getString(
            if (running) R.string.status_running else R.string.status_stopped
        )
        val color = ContextCompat.getColor(
            this, if (running) R.color.status_ok else R.color.status_off,
        )
        binding.statusText.setTextColor(color)
        binding.statusDot.background?.let {
            androidx.core.graphics.drawable.DrawableCompat.setTint(it.mutate(), color)
        }
        binding.toggleButton.text = getString(
            if (running) R.string.action_stop_proxy else R.string.action_start
        )
        binding.statusDetail.text = if (running) {
            tgLink()
        } else {
            getString(R.string.detail_stopped)
        }
        binding.openTelegramButton.isEnabled = running
        binding.copyLinkButton.isEnabled = running
        binding.statsCard.visibility = if (running) View.VISIBLE else View.GONE
    }

    private fun refreshStats() {
        if (!ProxyService.isRunning) {
            binding.statsText.text = ""
            return
        }
        binding.statsText.text = Stats.summary()
        binding.statUp.text = Const.humanBytes(Stats.bytesUp.get())
        binding.statDown.text = Const.humanBytes(Stats.bytesDown.get())
        binding.statActive.text = Stats.connectionsActive.get().toString()
        val route = dominantRoute()
        val ms = Stats.connectMsAvg
        binding.statRoute.text = if (ms > 0) getString(R.string.stat_route_ms, route, ms.toInt()) else route
    }

    /** Which upstream route carried most connections so far. */
    private fun dominantRoute(): String {
        val ws = Stats.connectionsWs.get()
        val cf = Stats.connectionsCfproxy.get()
        val relay = Stats.connectionsRelay.get()
        val tcp = Stats.connectionsTcpFallback.get()
        val max = maxOf(maxOf(ws, cf), maxOf(relay, tcp))
        if (max == 0L) return getString(R.string.placeholder_dash)
        val leaders = listOfNotNull(
            if (ws == max) R.string.route_ws else null,
            if (relay == max) R.string.route_relay else null,
            if (cf == max) R.string.route_cf else null,
            if (tcp == max) R.string.route_tcp else null,
        )
        return if (leaders.size == 1) getString(leaders[0]) else getString(R.string.route_mixed)
    }

    private fun renderLogs(lines: List<String>) {
        binding.logText.text = lines.joinToString("\n")
        scrollLogsToBottom()
    }

    private fun appendLogLine(line: String) {
        val current = binding.logText.text
        binding.logText.text = if (current.isEmpty()) line else "$current\n$line"
        scrollLogsToBottom()
    }

    private fun scrollLogsToBottom() {
        binding.logScroll.post { binding.logScroll.fullScroll(android.view.View.FOCUS_DOWN) }
    }

    // -------------------------------------------------------------- tg:// links

    /**
     * Builds the tg:// link from the persisted settings so it is correct even
     * when the engine is not running.
     */
    private fun tgLink(): String {
        val engine = ProxyService.engine()
        if (engine != null) return engine.tgLink()

        val host = if (settings.host == "0.0.0.0") localIp() else settings.host
        val ftls = settings.fakeTlsDomain
        return if (ftls.isEmpty()) {
            "tg://proxy?server=$host&port=${settings.port}&secret=dd${settings.secret}"
        } else {
            val hex = Const.toHex(ftls.toByteArray(Charsets.US_ASCII))
            "tg://proxy?server=$host&port=${settings.port}&secret=ee${settings.secret}$hex"
        }
    }

    private fun localIp(): String = runCatching {
        java.net.DatagramSocket().use { s ->
            com.flowseal.tgwsproxy.core.NetworkBinder.bind(s)
            s.connect(java.net.InetAddress.getByName("8.8.8.8"), 80)
            s.localAddress.hostAddress ?: "127.0.0.1"
        }
    }.getOrDefault("127.0.0.1")

    private fun openInTelegram() {
        val link = tgLink()
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(link))
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            startActivity(intent)
        } catch (e: Exception) {
            copyToClipboard(link)
            toast(getString(R.string.msg_no_telegram))
        }
    }

    private fun copyToClipboard(text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("tg-ws-proxy", text))
    }

    // -------------------------------------------------------------- first run

    private fun maybeShowFirstRun() {
        if (settings.firstRunDone) return
        AlertDialog.Builder(this)
            .setTitle(R.string.first_run_title)
            .setMessage(
                getString(
                    R.string.first_run_body,
                    settings.host, settings.port, settings.secret,
                ) + "\n\n" + getString(R.string.first_run_update_notice)
            )
            .setPositiveButton(R.string.first_run_ok) { _, _ -> settings.firstRunDone = true }
            .setCancelable(false)
            .show()
    }

    // ---------------------------------------------------------------- updates

    private fun appVersion(): String = UpdateManager.appVersion(this)

    /**
     * Opening the app counts as a chance to check (the periodic job may be
     * deferred for hours). With auto-install on this runs silently in the
     * background; otherwise a newer version is offered in a dialog.
     */
    private fun maybeCheckForUpdate() {
        if (!settings.autoUpdateCheck) return
        if (System.currentTimeMillis() - settings.lastUpdateCheck < UpdateManager.CHECK_INTERVAL_MS) return

        if (settings.autoInstallUpdates) {
            val ctx = applicationContext
            Thread({ UpdateManager.runScheduled(ctx) }, "update-check").apply { isDaemon = true }.start()
            return
        }
        settings.lastUpdateCheck = System.currentTimeMillis()
        val current = appVersion()
        Thread({
            val release = UpdateChecker.check(current) ?: return@Thread
            if (UpdateChecker.normalize(release.version) == settings.skippedUpdate) return@Thread
            handler.post { showUpdateDialog(release, current) }
        }, "update-check").apply { isDaemon = true }.start()
    }

    /** Explicit check from the menu or the button; always reports the outcome. */
    private fun checkForUpdateNow() {
        val current = appVersion()
        toast(getString(R.string.update_checking))
        settings.lastUpdateCheck = System.currentTimeMillis()
        Thread({
            val release = runCatching { UpdateChecker.check(current) }.getOrNull()
            handler.post {
                when {
                    release != null -> showUpdateDialog(release, current)
                    UpdateChecker.lastCheckFailed -> toast(getString(R.string.update_check_failed))
                    else -> toast(getString(R.string.update_none, current))
                }
            }
        }, "update-check-manual").apply { isDaemon = true }.start()
    }

    private fun showUpdateDialog(release: UpdateChecker.Release, current: String) {
        if (isFinishing || isDestroyed) return
        val notes = release.notes.trim().take(700)
        val message = buildString {
            append(getString(R.string.update_installed, current))
            if (release.sizeBytes > 0) {
                append(" · ").append(Const.humanBytes(release.sizeBytes))
            }
            append("\n\n")
            append(getString(R.string.update_signature_warning))
            if (notes.isNotEmpty()) append("\n\n").append(notes)
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.update_title, release.version))
            .setMessage(message)
            .setPositiveButton(R.string.action_update_now) { _, _ -> downloadUpdate(release) }
            .setNeutralButton(R.string.action_skip_version) { _, _ ->
                settings.skippedUpdate = UpdateChecker.normalize(release.version)
            }
            .setNegativeButton(R.string.action_later, null)
            .show()
    }

    private fun downloadUpdate(release: UpdateChecker.Release) {
        if (!UpdateInstaller.canInstall(this)) {
            AlertDialog.Builder(this)
                .setTitle(R.string.update_permission_title)
                .setMessage(R.string.update_permission_body)
                .setPositiveButton(R.string.action_grant) { _, _ ->
                    UpdateInstaller.openInstallPermission(this)
                }
                .setNegativeButton(R.string.action_cancel, null)
                .show()
            return
        }

        val progress = AlertDialog.Builder(this)
            .setTitle(getString(R.string.update_title, release.version))
            .setMessage(getString(R.string.update_downloading, 0))
            .setCancelable(false)
            .show()

        val ctx = applicationContext
        Thread({
            try {
                UpdateManager.installRelease(ctx, release) { percent ->
                    handler.post {
                        progress.setMessage(
                            if (percent >= 100) getString(R.string.update_installing)
                            else getString(R.string.update_downloading, percent)
                        )
                    }
                }
                // The session result (a confirmation screen or a restart) comes
                // through UpdateReceiver.
                handler.postDelayed({ runCatching { progress.dismiss() } }, 1_500)
            } catch (e: Exception) {
                Logger.w("Update failed: $e")
                handler.post {
                    runCatching { progress.dismiss() }
                    toast(
                        getString(
                            R.string.update_download_failed,
                            e.message ?: e.javaClass.simpleName,
                        )
                    )
                }
            }
        }, "update-download").apply { isDaemon = true }.start()
    }

    private fun openUrl(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    private fun openReleasesPage() {
        runCatching {
            startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(UpdateChecker.RELEASES_PAGE))
            )
        }
    }

    // ------------------------------------------------------------- diagnostics

    private fun runDiagnostics() {
        val progress = AlertDialog.Builder(this)
            .setTitle(R.string.diagnostics_title)
            .setMessage(R.string.diagnostics_running)
            .setCancelable(false)
            .show()
        Thread({
            val cfg = settings.toProxyConfig()
            val report = Diagnostics.run(cfg)
            handler.post {
                runCatching { progress.dismiss() }
                if (isFinishing || isDestroyed) return@post
                AlertDialog.Builder(this)
                    .setTitle(R.string.diagnostics_title)
                    .setMessage(report.text())
                    .setPositiveButton(R.string.about_close, null)
                    .setNeutralButton(R.string.action_copy_result) { _, _ ->
                        copyToClipboard(report.text())
                        toast(getString(R.string.msg_copied))
                    }
                    .show()
            }
        }, "diagnostics").apply { isDaemon = true }.start()
    }

    private fun openNotificationSettings() {
        val intent = if (Build.VERSION.SDK_INT >= 26) {
            Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName)
        } else {
            Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.parse("package:$packageName"))
        }
        runCatching { startActivity(intent) }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return
        val granted = ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun toast(msg: String) {
        Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()
    }
}
