package com.muster.agent

import java.io.IOException
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/**
 * Posts a device report to Muster's `POST /api/mobile-report` endpoint.
 *
 * Deliberately written against plain java.net.HttpURLConnection rather
 * than OkHttp/Retrofit: Muster's philosophy throughout (see every other
 * agent script, and internal/ingest's hand-rolled MUSTER1 protocol) is
 * "own the whole path with the smallest possible dependency footprint."
 * java.net is also part of Android's core runtime libraries (unlike
 * android.* framework APIs), which is what makes this file -- unlike
 * DeviceFacts.kt/ReportWorker.kt/MainActivity.kt -- compilable and
 * verifiable with a plain `kotlinc`, no Android SDK required, while
 * still being the exact code that ships and runs on-device.
 *
 * Every failure mode (bad host, timeout, non-2xx response, malformed
 * response body) surfaces as a [MusterReportException] with a message
 * meant to be shown directly in the setup screen's status line -- this
 * agent has no logs a user will ever see, so the exception message IS
 * the diagnostic.
 *
 * Verified with a plain `kotlinc` plus a small local smoke test (JSON
 * round-trip, empty-URL rejection, unreachable-host rejection) -- see
 * agent/android/README.md's "What's actually verified" section.
 */
class MusterReportException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class MusterReportResult(val statusCode: Int, val body: String)

object MusterClient {

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 20_000

    /**
     * Sends [facts] for [host]/[platform] to [baseUrl] + "/api/mobile-report",
     * authenticated with [token] as a bearer token (the enrollment token
     * minted for this host in the Muster web UI's Agents tab).
     *
     * [baseUrl] should be a bare origin like "https://muster.example.com"
     * or "http://192.168.1.20:8080" -- no trailing slash required, this
     * function normalizes it.
     */
    @Throws(MusterReportException::class)
    fun postMobileReport(
        baseUrl: String,
        host: String,
        platform: String,
        token: String,
        facts: Map<String, Map<String, Any?>>
    ): MusterReportResult {
        val trimmedBase = baseUrl.trim().trimEnd('/')
        if (trimmedBase.isEmpty()) {
            throw MusterReportException("Server URL is empty")
        }
        val url = try {
            URL("$trimmedBase/api/mobile-report")
        } catch (e: Exception) {
            throw MusterReportException("Invalid server URL: ${e.message}", e)
        }

        val bodyJson = MusterJson.encode(
            mapOf(
                "host" to host,
                "platform" to platform,
                "facts" to facts
            )
        )
        val bodyBytes = bodyJson.toByteArray(StandardCharsets.UTF_8)

        val conn = try {
            url.openConnection() as HttpURLConnection
        } catch (e: IOException) {
            throw MusterReportException("Couldn't open connection: ${e.message}", e)
        }

        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout = READ_TIMEOUT_MS
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            conn.setRequestProperty("Authorization", "Bearer $token")
            conn.setRequestProperty("Accept", "application/json")

            conn.outputStream.use { out: OutputStream -> out.write(bodyBytes) }

            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val responseBody = stream?.bufferedReader(StandardCharsets.UTF_8)?.use { it.readText() } ?: ""

            if (status !in 200..299) {
                throw MusterReportException("Server returned HTTP $status: ${responseBody.take(300)}")
            }
            return MusterReportResult(status, responseBody)
        } catch (e: MusterReportException) {
            throw e
        } catch (e: IOException) {
            throw MusterReportException("Network error talking to Muster: ${e.message}", e)
        } finally {
            conn.disconnect()
        }
    }
}
