/*******************************************************************************
 * @file         DeviceFacts.kt
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

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.StatFs

/**
 * Collects the same kind of "cheap, always-available, no special
 * permission" facts the desktop agents read via /proc, WMI, or system_profiler
 * -- here read via android.os/android.net instead. Deliberately skips
 * anything that would need a runtime permission grant (fine location for
 * Wi-Fi SSID, phone state for IMEI/subscriber ID) or that's sensitive in
 * a way those other agents' facts aren't (precise location, contacts,
 * installed-app list) -- this agent reports device posture, not personal
 * data. See agent/android/README.md for the full list and rationale.
 *
 * NOT verified by a compiler in this environment -- android.* framework
 * classes require the Android SDK, which isn't reachable here (see
 * agent/android/README.md). Reviewed by hand against the public
 * BatteryManager/StatFs/ConnectivityManager/Build API surface; the real
 * verification step is building this in Android Studio.
 */
object DeviceFacts {

    fun collect(context: Context): Map<String, Map<String, Any?>> {
        val facts = LinkedHashMap<String, Map<String, Any?>>()
        facts["system_summary"] = systemSummary()
        facts["mobile_status"] = mobileStatus(context)
        return facts
    }

    private fun systemSummary(): Map<String, Any?> = mapOf(
        "os" to "android",
        "os_version" to Build.VERSION.RELEASE,
        "sdk_int" to Build.VERSION.SDK_INT,
        "manufacturer" to Build.MANUFACTURER,
        "brand" to Build.BRAND,
        "model" to Build.MODEL,
        "device" to Build.DEVICE,
        "agent_version" to BuildConfig.VERSION_NAME
    )

    private fun mobileStatus(context: Context): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()

        // Battery: read via the ACTION_BATTERY_CHANGED sticky intent
        // rather than the BATTERY_PROPERTY_* ints -- works identically
        // across OEMs and API 26+ without any extra permission.
        try {
            val batteryIntent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            if (batteryIntent != null) {
                val level = batteryIntent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                val scale = batteryIntent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                if (level >= 0 && scale > 0) {
                    out["battery_percent"] = (level * 100) / scale
                }
                val status = batteryIntent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
                out["battery_charging"] = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                    status == BatteryManager.BATTERY_STATUS_FULL
            }
        } catch (e: Exception) {
            out["battery_error"] = e.message
        }

        // Storage: internal app-accessible storage, the same "how full is
        // the primary disk" question df -Pk answers for the Linux agent
        // -- StatFs on the data directory is the closest Android
        // equivalent without needing MANAGE_EXTERNAL_STORAGE.
        try {
            val stat = StatFs(context.filesDir.path)
            val blockSize = stat.blockSizeLong
            out["storage_free_mb"] = (stat.availableBlocksLong * blockSize) / (1024 * 1024)
            out["storage_total_mb"] = (stat.blockCountLong * blockSize) / (1024 * 1024)
        } catch (e: Exception) {
            out["storage_error"] = e.message
        }

        // Network transport type only -- no SSID/BSSID (that needs
        // ACCESS_FINE_LOCATION on modern Android and isn't posture data
        // this tool has any use for).
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val caps = cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            out["network_type"] = when {
                caps == null -> "none"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                else -> "other"
            }
        } catch (e: Exception) {
            out["network_type"] = "unknown"
        }

        try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            val memInfo = ActivityManager.MemoryInfo()
            am?.getMemoryInfo(memInfo)
            if (memInfo.totalMem > 0) {
                out["memory_total_mb"] = memInfo.totalMem / (1024 * 1024)
                out["memory_available_mb"] = memInfo.availMem / (1024 * 1024)
            }
        } catch (e: Exception) {
            out["memory_error"] = e.message
        }

        return out
    }
}
