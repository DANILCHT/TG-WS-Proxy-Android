package com.flowseal.tgwsproxy.core

import android.util.Log

/**
 * Ring-buffer logger: mirrors messages to logcat and keeps the last N lines
 * in memory so the UI can show them (the desktop app opens a log file instead).
 */
object Logger {

    const val TAG = "TgWsProxy"
    private const val MAX_LINES = 600

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
        val line = "$ts  $level  $msg"
        synchronized(lines) {
            lines.addLast(line)
            while (lines.size > MAX_LINES) lines.removeFirst()
        }
        val snap = synchronized(listeners) { listeners.toList() }
        for (l in snap) runCatching { l(line) }
    }
}
