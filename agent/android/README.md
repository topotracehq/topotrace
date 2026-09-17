# Muster Agent for Android

A small native Android app that periodically reports basic device facts
(OS version, battery, storage, network transport) to a Muster server,
over the same `POST /api/mobile-report` endpoint the [iOS Shortcuts
flow](../ios/README.md) uses. It's the mobile counterpart to the
Linux/macOS/Windows agent scripts in this directory -- same idea (report
in, get inventoried and posture-scored), different transport (JSON over
HTTPS instead of the raw MUSTER1 TCP protocol, since a phone can't run a
cron job or a DaemonSet).

## Setting it up

1. In the Muster web dashboard, open the **Agents** tab, enter an admin
   token if you haven't already, and create a new enrollment with
   platform **Android**. This mints a one-time enrollment token tied to
   that host name -- copy it now, it's shown only once (see
   `internal/api/server.go`'s `handleCreateEnrollment`).
2. Build and install this app (see "Building" below).
3. On the device, open Muster Agent and enter:
   - **Muster server URL** -- e.g. `http://192.168.1.20:8080`, whatever
     `-listen`/your ingress has the API server on. Must be reachable from
     the phone (same LAN, VPN, or a public URL).
   - **Host name** -- exactly the host name you enrolled in step 1.
   - **Enrollment token** -- from step 1.
4. Tap **Report now** to confirm it works, then **Save & schedule** to
   start background reporting every 6 hours (see `ReportWorker`'s
   `REPORT_INTERVAL_HOURS`; WorkManager's practical minimum is 15
   minutes but a phone's posture doesn't need to be checked that often).

The token this app holds only ever authorizes fact reports for the one
host name it was minted for -- see `model.Enrollment`'s doc comment on
the server side. If the phone is lost, revoke the enrollment from the
Agents tab; nothing else on the account is exposed by that token.

## What it reports

- `system_summary`: `os` (always `"android"`), `os_version`, `sdk_int`,
  `manufacturer`, `brand`, `model`, `device`, `agent_version`.
- `mobile_status`: `battery_percent`, `battery_charging`,
  `storage_free_mb`, `storage_total_mb` (internal app storage, via
  `StatFs` -- the closest equivalent to `df -Pk` without
  `MANAGE_EXTERNAL_STORAGE`), `network_type` (`wifi`/`cellular`/
  `ethernet`/`none`/`other`), `memory_total_mb`, `memory_available_mb`.

Deliberately excluded: Wi-Fi SSID/BSSID (needs `ACCESS_FINE_LOCATION` on
modern Android), IMEI/subscriber ID (needs `READ_PHONE_STATE`, and isn't
posture data), installed-app list, contacts, precise location -- none of
that is something this tool has a use for, and asking for those
permissions would make a security-inventory app look like the thing it's
meant to help you find.

## Building

Requires [Android Studio](https://developer.android.com/studio)
(Giraffe/2023.3+ recommended) and JDK 17.

1. Open the `agent/android/` directory as a project in Android Studio.
2. This repo does **not** commit a Gradle wrapper jar (this project was
   scaffolded in an environment with no network access to
   services.gradle.org to fetch one -- see the note in the root repo's
   status doc if you're curious why). `gradle/wrapper/gradle-wrapper.properties`
   is already there pointing at Gradle 8.4; Android Studio will offer to
   regenerate the wrapper automatically on first open ("Gradle wrapper
   not found, create one?"), or right-click the root project in the
   Gradle tool window → **Add Gradle Wrapper**. Accept it once and every
   subsequent open/build works normally, including from the command line
   (`./gradlew assembleDebug`).
3. Let Gradle sync (downloads AGP 8.2.2, Kotlin 1.9.22, AndroxX/Material/
   WorkManager -- all from Google's and Maven Central's repositories).
4. Run on a device or emulator (**Run ▸ Run 'app'**), or
   **Build ▸ Build Bundle(s) / APK(s) ▸ Build APK(s)** for a sideloadable
   APK.

## What's actually verified, and what isn't

This project was written in an environment with **no reachable Android
SDK and no reachable Google/Maven Central mirrors** (`dl.google.com`,
`maven.google.com`, `repo1.maven.org`, and `services.gradle.org` were all
blocked by the sandbox's egress allowlist) -- so nothing here has gone
through a real Android Gradle Plugin build yet. To still get real
compiler verification where possible, the app is split by what could be
checked:

- **`MusterJson.kt` and `MusterClient.kt`** use nothing outside the
  plain JDK (`java.net`, `java.io`, `kotlin.*` -- no `android.*` or
  `androidx.*` imports), so they were compiled and run with a
  plain `kotlinc` (Kotlin 1.3.31, installed via `apt-get install kotlin`
  -- the one package source Ubuntu's own apt mirror made reachable) and
  exercised with a small standalone smoke test: JSON round-trip
  (nested maps, string escaping including quotes/newlines), an
  empty-URL rejection, and an unreachable-host rejection, all producing
  the expected `MusterReportException` messages. This is the exact code
  that ships in the app -- `java.net.HttpURLConnection` is part of
  Android's core runtime libraries too, not an Android-SDK-only API, so
  nothing changes between the verified version and the on-device one.
- **`DeviceFacts.kt`, `ReportWorker.kt`, `MainActivity.kt`, `Prefs.kt`**,
  the Gradle files, the manifest, and the resource XML were all written
  by hand against the public `android.os`/`android.net`/`androidx.work`/
  `androidx.appcompat` API surfaces and reviewed for balanced braces/
  parens and consistent naming, but **none of it has been compiled**.
  The real verification step is opening this in Android Studio per
  "Building" above and confirming a clean Gradle sync and build --
  please do that before relying on this for anything, and report back
  whatever Gradle's first error is if sync doesn't go cleanly; API
  surfaces do drift between AGP/library versions and there's a real
  chance a signature or two needs adjusting.
