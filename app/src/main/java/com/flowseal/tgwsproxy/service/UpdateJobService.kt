package com.flowseal.tgwsproxy.service

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import com.flowseal.tgwsproxy.core.Logger
import com.flowseal.tgwsproxy.core.Settings
import com.flowseal.tgwsproxy.core.UpdateManager

/**
 * Periodic update check that runs even when neither the app nor the proxy is
 * open. The actual rate limit lives in [UpdateManager.runScheduled].
 */
class UpdateJobService : JobService() {

    companion object {
        private const val JOB_ID = 4201
        private const val PERIOD_MS = 12 * 60 * 60 * 1000L

        /** Idempotent: (re)schedules or cancels according to the settings. */
        fun schedule(context: Context) {
            val js = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            if (!Settings.get(context).autoUpdateCheck) {
                js.cancel(JOB_ID)
                return
            }
            if (js.allPendingJobs.any { it.id == JOB_ID }) return
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, UpdateJobService::class.java))
                .setPeriodic(PERIOD_MS)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(true)
                .build()
            runCatching { js.schedule(job) }
                .onFailure { Logger.d("Update job not scheduled: $it") }
        }
    }

    @Volatile
    private var worker: Thread? = null

    override fun onStartJob(params: JobParameters): Boolean {
        val t = Thread({
            try {
                UpdateManager.runScheduled(applicationContext)
            } catch (e: Exception) {
                Logger.d("Scheduled update check failed: $e")
            } finally {
                jobFinished(params, false)
            }
        }, "update-job")
        t.isDaemon = true
        worker = t
        t.start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        worker?.interrupt()
        return true
    }
}
