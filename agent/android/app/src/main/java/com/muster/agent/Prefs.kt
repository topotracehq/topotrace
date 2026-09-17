package com.muster.agent

import android.content.Context
import android.content.SharedPreferences

/**
 * Thin wrapper around the app's SharedPreferences file -- three plain
 * strings (server URL, host name, enrollment token), nothing else. No
 * encryption: the token is a narrow, revocable, host-scoped credential
 * (see model.Enrollment's doc comment on the server) that only ever
 * authorizes this one host's fact reports, the same trust level as the
 * plaintext token file the Linux/macOS/Windows agent scripts read from
 * a --token flag or an unencrypted config -- not worth the added
 * complexity of Android's EncryptedSharedPreferences/Keystore for a
 * credential this narrow. Revoking it from the Agents tab is the actual
 * mitigation if a device is lost, not local-at-rest encryption.
 */
class Prefs(context: Context) {
    private val sp: SharedPreferences =
        context.getSharedPreferences("muster_agent_prefs", Context.MODE_PRIVATE)

    var serverUrl: String
        get() = sp.getString(KEY_SERVER_URL, "") ?: ""
        set(value) = sp.edit().putString(KEY_SERVER_URL, value).apply()

    var hostName: String
        get() = sp.getString(KEY_HOST_NAME, "") ?: ""
        set(value) = sp.edit().putString(KEY_HOST_NAME, value).apply()

    var token: String
        get() = sp.getString(KEY_TOKEN, "") ?: ""
        set(value) = sp.edit().putString(KEY_TOKEN, value).apply()

    var lastReportAt: Long
        get() = sp.getLong(KEY_LAST_REPORT_AT, 0L)
        set(value) = sp.edit().putLong(KEY_LAST_REPORT_AT, value).apply()

    fun isConfigured(): Boolean = serverUrl.isNotBlank() && hostName.isNotBlank() && token.isNotBlank()

    companion object {
        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_HOST_NAME = "host_name"
        private const val KEY_TOKEN = "token"
        private const val KEY_LAST_REPORT_AT = "last_report_at"
    }
}
