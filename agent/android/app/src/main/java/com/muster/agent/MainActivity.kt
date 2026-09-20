/*******************************************************************************
 * @file         MainActivity.kt
 * @brief        Part of the Muster agent module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package com.muster.agent

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.muster.agent.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Single-screen setup UI: enter the Muster server URL, a host name, and
 * the enrollment token minted for this device in the web dashboard's
 * Agents tab (see internal/webui/static/app.js's showAgents/installSnippet
 * -- Android's install-snippet branch tells the operator to paste those
 * same three values in here). Save schedules the recurring background
 * report via [ReportWorker.schedule]; Report Now runs one report
 * immediately and shows the result inline, the fastest way to confirm
 * the token/URL/host are actually correct before walking away.
 *
 * NOT verified by a compiler in this environment -- depends on
 * androidx.appcompat/lifecycle and generated view-binding classes, all
 * of which need the Android Gradle Plugin. Reviewed by hand against the
 * public AppCompatActivity/lifecycleScope API surface; the real
 * verification step is building this in Android Studio.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var prefs: Prefs

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        prefs = Prefs(this)

        loadPrefsIntoFields()
        updateStatusFromPrefs()

        binding.buttonSave.setOnClickListener { onSave() }
        binding.buttonReportNow.setOnClickListener { onReportNow() }
    }

    private fun loadPrefsIntoFields() {
        if (prefs.serverUrl.isNotBlank()) binding.inputServerUrl.setText(prefs.serverUrl)
        if (prefs.hostName.isNotBlank()) binding.inputHostName.setText(prefs.hostName)
        if (prefs.token.isNotBlank()) binding.inputToken.setText(prefs.token)
    }

    private fun currentFieldValues(): Triple<String, String, String> = Triple(
        binding.inputServerUrl.text?.toString()?.trim().orEmpty(),
        binding.inputHostName.text?.toString()?.trim().orEmpty(),
        binding.inputToken.text?.toString()?.trim().orEmpty()
    )

    private fun onSave() {
        val (serverUrl, hostName, token) = currentFieldValues()
        if (serverUrl.isBlank() || hostName.isBlank() || token.isBlank()) {
            binding.textStatus.text = getString(R.string.status_not_configured)
            return
        }
        prefs.serverUrl = serverUrl
        prefs.hostName = hostName
        prefs.token = token
        ReportWorker.schedule(applicationContext)
        binding.textStatus.text = getString(R.string.status_saved)
    }

    private fun onReportNow() {
        val (serverUrl, hostName, token) = currentFieldValues()
        if (serverUrl.isBlank() || hostName.isBlank() || token.isBlank()) {
            binding.textStatus.text = getString(R.string.status_not_configured)
            return
        }
        binding.textStatus.text = getString(R.string.status_reporting)
        binding.buttonReportNow.isEnabled = false

        lifecycleScope.launch {
            try {
                val facts = DeviceFacts.collect(applicationContext)
                withContext(Dispatchers.IO) {
                    MusterClient.postMobileReport(
                        baseUrl = serverUrl,
                        host = hostName,
                        platform = "android",
                        token = token,
                        facts = facts
                    )
                }
                prefs.lastReportAt = System.currentTimeMillis()
                updateStatusFromPrefs()
            } catch (e: MusterReportException) {
                binding.textStatus.text = getString(R.string.status_error, e.message ?: "unknown error")
            } finally {
                binding.buttonReportNow.isEnabled = true
            }
        }
    }

    private fun updateStatusFromPrefs() {
        val last = prefs.lastReportAt
        if (last > 0) {
            val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
            binding.textStatus.text = getString(R.string.status_success, fmt.format(Date(last)))
        }
    }
}
