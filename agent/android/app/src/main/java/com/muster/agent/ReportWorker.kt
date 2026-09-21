/*******************************************************************************
 * @file         ReportWorker.kt
 * @brief        Part of the TopoTrace agent module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package com.muster.agent

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.Constraints
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Background reporting job -- WorkManager's periodic minimum is 15
 * minutes, but a device posture check doesn't need that cadence, so
 * this runs every [REPORT_INTERVAL_HOURS] hours by default, the same
 * "periodic snapshot, not continuous streaming" model the DaemonSet/
 * CronJob agents use server-side. WorkManager itself (not this class)
 * handles surviving process death, Doze-mode deferral, and
 * re-scheduling after a reboot, since the periodic work request is
 * enqueued with ExistingPeriodicWorkPolicy.KEEP in [schedule].
 *
 * NOT verified by a compiler in this environment -- depends on
 * androidx.work, which is only resolvable with the Android Gradle
 * Plugin's dependency graph. Reviewed by hand against the public
 * CoroutineWorker/WorkManager API surface; the real verification step
 * is building this in Android Studio.
 */
class ReportWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val prefs = Prefs(applicationContext)
        if (!prefs.isConfigured()) {
            return Result.failure()
        }

        return try {
            val facts = DeviceFacts.collect(applicationContext)
            withContext(Dispatchers.IO) {
                MusterClient.postMobileReport(
                    baseUrl = prefs.serverUrl,
                    host = prefs.hostName,
                    platform = "android",
                    token = prefs.token,
                    facts = facts
                )
            }
            prefs.lastReportAt = System.currentTimeMillis()
            Result.success()
        } catch (e: MusterReportException) {
            // Transient network/server issues get retried by WorkManager's
            // backoff policy; a report that's simply misconfigured (bad
            // token, bad host) would fail identically every retry, but
            // there's no cheap way to tell those apart from here, so
            // retry() in both cases and let the next report attempt --
            // and any Report Now failures if the user manually checks
            // status -- be the actual feedback loop.
            Result.retry()
        }
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "muster_periodic_report"
        private const val REPORT_INTERVAL_HOURS = 6L

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = PeriodicWorkRequestBuilder<ReportWorker>(REPORT_INTERVAL_HOURS, TimeUnit.HOURS)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(UNIQUE_WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_WORK_NAME)
        }
    }
}
