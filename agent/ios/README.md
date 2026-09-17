# Muster Agent for iOS (Shortcuts-based)

There is no native iOS app here, and that's a deliberate choice, not a
gap: Apple's app sandboxing gives a regular App Store app no way to run
a background job on its own schedule, read another app's battery/
storage stats, or start automatically at boot the way the Linux/macOS/
Windows agent scripts or the [Android app](../android/) can. The only
way to get real unattended background execution on iOS is either Mobile
Device Management (MDM) enrollment -- a whole separate fleet-management
system, out of scope for what Muster is -- or the built-in **Shortcuts**
app's Personal Automations, which run with the user's own already-granted
permissions on a schedule the user defines. This doc is the second
option: a fully manual, no-code walkthrough for wiring Shortcuts up to
report to Muster's `POST /api/mobile-report` endpoint, the same JSON
endpoint the [Android agent](../android/) uses.

**Read this whole doc before starting** -- particularly "Limitations"
below. This is a best-effort, user-attended setup, not an unattended
fleet agent; set expectations accordingly before enrolling a device.

## What you'll build

A Shortcuts **Personal Automation** that, on a schedule, gathers a
handful of device details, builds them into the same JSON shape the
Android app sends, and POSTs it to Muster with the enrollment token as a
bearer token -- no scripting, only Shortcuts' built-in actions.

## Before you start

In the Muster web dashboard's **Agents** tab (enter an admin token if
you haven't already), create a new enrollment with platform **iOS**.
Copy the token shown -- it's shown once. You'll paste it into one
Shortcuts action below, and it authorizes fact reports for that one host
name only (see `model.Enrollment`'s doc comment on the server side); if
the device is lost, revoke it from that same tab.

## Building the Shortcut

1. Open **Shortcuts** on the iPhone/iPad. Go to the **Automation** tab →
   **+** → **Create Personal Automation**.
2. Pick a trigger of **Time of Day**, set a time, and set it to repeat
   **Daily**. (Shortcuts automations don't support an arbitrary "every N
   hours" trigger -- if you want more than once a day, add a second and
   third Time of Day automation at different times, each running the
   same shortcut below.)
3. Tap **Next**, then **Add Action**, and add these actions in order:

   **a. Get Device Details -- System Version**
   Search for "Get Device Details", add it, and set its detail dropdown
   to **System Version**. Tap the result, choose **Rename Variable**,
   name it `osVersion`.

   **b. Get Device Details -- Model**
   Add a second "Get Device Details" action, detail set to **Model**.
   Rename its output variable to `deviceModel`.

   **c. Get Device Details -- Device Name**
   Detail set to **Device Name**. Rename output to `deviceName`.

   **d. Get Device Details -- Battery Level**
   Detail set to **Battery Level**. Rename output to `batteryLevel`.

   **e. Get Device Details -- Available Storage**
   Detail set to **Available Storage**. Rename output to `storageFree`.

   **f. Get Device Details -- Total Storage**
   Detail set to **Total Storage**. Rename output to `storageTotal`.

   **g. Get Device Details -- Wi-Fi**
   Detail set to **Wi-Fi**. Rename output to `wifiStatus`.

   Each of these is genuinely a separate "Get Device Details" action --
   Shortcuts only returns one detail per action, there's no batch call.

   **h. Dictionary (facts.system_summary)**
   Add a **Dictionary** action. Add these key/value pairs, using the
   variables above for values (tap the value field, then tap the ⓧ
   variable picker instead of typing):
   - `os` → text `ios`
   - `os_version` → variable `osVersion`
   - `model` → variable `deviceModel`
   - `device_name` → variable `deviceName`

   Rename this Dictionary's output to `factsSystemSummary`.

   **i. Dictionary (facts.mobile_status)**
   Add another **Dictionary** action:
   - `battery_percent` → variable `batteryLevel`
   - `storage_free` → variable `storageFree`
   - `storage_total` → variable `storageTotal`
   - `wifi_status` → variable `wifiStatus`

   Rename its output to `factsMobileStatus`. (`storage_free`/
   `storage_total` arrive from Shortcuts already formatted, e.g. "128
   GB" rather than a bare number of megabytes like the Android app
   sends -- that's fine, Muster stores fact values as opaque JSON, not a
   fixed numeric schema, so a formatted string is a perfectly valid
   value; it just won't feed anything that expects a specific unit.)

   **j. Dictionary (facts)**
   Add a **Dictionary** action:
   - `system_summary` → variable `factsSystemSummary`
   - `mobile_status` → variable `factsMobileStatus`

   Rename its output to `factsRoot`.

   **k. Dictionary (request body)**
   Add a final **Dictionary** action -- this is the whole request body:
   - `host` → text: the exact host name you enrolled (e.g. `johns-iphone`)
   - `platform` → text `ios`
   - `facts` → variable `factsRoot`

   Rename its output to `requestBody`.

   **l. Get Contents of URL**
   Add **Get Contents of URL**. Configure:
   - URL: `https://your-muster-server/api/mobile-report` (use your
     actual server address -- same host/port the Android app or web
     dashboard uses)
   - Method: **POST**
   - Headers: add `Authorization` → `Bearer YOUR_ENROLLMENT_TOKEN` (paste
     the token from "Before you start")
   - Request Body: **JSON**, set to variable `requestBody`

4. Tap **Next**, then turn **off** "Ask Before Running" -- with it on,
   iOS pops a confirmation banner every single time the automation fires
   and the shortcut won't run at all until you tap it, defeating the
   point of a scheduled report. With it off, iOS still briefly shows a
   notification that it ran, but doesn't wait for a tap.

## Verifying it

Open the shortcut from the Shortcuts tab (not the Automation trigger)
and run it manually once. If it fails, Shortcuts shows which action
errored -- the most common causes are a typo'd URL, a missing/incorrect
Authorization header, or a `host` value that doesn't exactly match the
enrollment's host name (`authorizedIngestToken` on the server matches
by exact host name against the enrollment record, not a prefix or
case-insensitive match). A successful run shows no error and a fresh
`last_seen` for that host in the Muster dashboard.

## Limitations

- **No true background execution.** This is a scheduled automation
  running with your existing app permissions, not a system daemon --
  iOS can skip or delay a Time of Day automation (Low Power Mode, the
  device being off, Shortcuts having been force-quit and not reopened
  recently) far more often than a systemd timer or WorkManager job
  would. Treat "iOS host looks stale" as expected background noise, not
  necessarily a real problem, more than you would for the other agents.
- **At most a few times a day.** Shortcuts has no interval trigger --
  only fixed times, so 6+ separate Time of Day automations is the
  practical ceiling before it gets unwieldy to maintain.
- **No remediation.** iOS hosts can report facts via this flow, but
  there's no way for Shortcuts to receive and execute a queued
  remediation action the way the desktop agents' TCP protocol does --
  `POST /api/mobile-report` only ever accepts a report, it never hands
  anything back. `internal/remediate` actions simply won't apply to iOS
  hosts; that's expected, not a bug to fix here.
- **Coarser data.** Shortcuts' "Get Device Details" surface is small and
  Apple-curated -- there's no equivalent of the Linux agent's installed-
  package list, listening ports, or firewall status. This flow is meant
  to answer "is this phone still checked in, roughly how's its battery/
  storage," not to give iOS the same depth of posture data as a server
  or desktop.

## Unverified

Every action name, detail option, and behavior described above (Get
Device Details' detail list, Dictionary action nesting, "Ask Before
Running") is written from the public, documented Shortcuts action set,
but this doc was written in an environment with no iOS device or
Shortcuts app available to actually build and run it against a live
Muster server. Exact detail-picker wording can shift slightly between
iOS versions. Please build it once against a running Muster instance
and let this doc be corrected against whatever you actually see on
screen, the same "unverified until run on real hardware" caveat that
applies to the Android app's Gradle build.
