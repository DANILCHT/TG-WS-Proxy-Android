package com.flowseal.tgwsproxy.core

import android.util.Log

/**
 * Ring-buffer logger: mirrors messages to logcat and keeps the last N lines
 * in memory so the UI can show them (the desktop app opens a log file instead).
 */
object Logger {

    const val TAG = "TgWsProxy"
    private const val MAX_LINES = 600

    /**
     * Port of proxy/utils.py::DomainCensorFilter — user domains (fronting SNI,
     * CF workers, Fake TLS) must not end up in logs or bug reports. Telegram's
     * own domains stay readable.
     */
    private val DOMAIN_RE = Regex(
        """(?<![\w-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![\w-])"""
    )

    fun censorDomains(msg: String): String = DOMAIN_RE.replace(msg) { m ->
        val domain = m.value
        val normalized = domain.lowercase().trimEnd('.')
        if (normalized == "telegram.org" ||
            normalized.endsWith(".telegram.org") ||
            normalized.endsWith(".log")
        ) {
            return@replace domain
        }
        val parts = domain.split(".")
        if (parts.size < 2) return@replace domain
        parts.mapIndexed { i, part ->
            if (i == parts.lastIndex) part
            else part.take(part.length / 2) + "*".repeat(part.length - part.length / 2)
        }.joinToString(".")
    }

    @Volatile
    var verbose: Boolean = false

    private val lines = ArrayDeque<String>()
    private val listeners = mutableListOf<(String) -> Unit>()

    fun addListener(l: (String) -> Unit) = synchronized(listeners) { listeners.add(l) }

    fun removeListener(l: (String) -> Unit) = synchronized(listeners) { listeners.remove(l) }

    fun snapshot(): List<String> = synchronized(lines) { lines.toList() }

    fun clear() = synchronized(lines) { lines.clear() }

    fun d(msg: String) {
        if (!verbose) return
        Log.d(TAG, msg)
        store("D", msg)
    }

    fun i(msg: String) {
        Log.i(TAG, msg)
        store("I", msg)
    }

    fun w(msg: String) {
        Log.w(TAG, msg)
        store("W", msg)
    }

    fun e(msg: String, tr: Throwable? = null) {
        if (tr != null) Log.e(TAG, msg, tr) else Log.e(TAG, msg)
        store("E", if (tr != null) "$msg: $tr" else msg)
    }

    private fun store(level: String, msg: String) {
        val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())
        val line = "$ts  $level  ${censorDomains(msg)}"
        synchronized(lines) {
            lines.addLast(line)
            while (lines.size > MAX_LINES) lines.removeFirst()
        }
        val snap = synchronized(listeners) { listeners.toList() }
        for (l in snap) runCatching { l(line) }
    }
}
