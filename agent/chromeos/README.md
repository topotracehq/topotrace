# Muster Agent for ChromeOS

A small Manifest V3 Chrome extension that periodically reports managed
Chromebook device facts (serial number, asset ID, CPU/memory/storage,
network) to a Muster server, over the same `POST /api/mobile-report`
endpoint the [Android app](../android/) and the [iOS Shortcuts
flow](../ios/README.md) use. It's the ChromeOS counterpart to those two
mobile agents -- same idea (report in, get inventoried and
posture-scored), different transport (a Chrome extension's background
service worker instead of a native app or a Shortcuts automation, since
that's the only way to get unattended background execution and
enterprise-only device attributes on ChromeOS).

## Why an extension, not the Android agent via ARC++

ChromeOS can run Android apps through ARC++, so reusing the [Android
agent](../android/) as-is was considered and rejected: ARC++ apps see
Android's own device APIs (`android.os.Build`,
`ActivityManager.MemoryInfo`, ...), not ChromeOS's actual managed-device
identity (serial number, asset ID, enrollment info) or ChromeOS-specific
hardware info -- reusing the Android agent would report "an Android app
running somewhere," not "this Chromebook." A native Manifest V3
extension using `chrome.enterprise.*` and `chrome.system.*` gives Muster
a distinct ChromeOS story instead, which is the actual point: this is
also exactly the platform split a product like Island's Enterprise
Browser is built around -- ChromeOS is treated as its own managed
platform, not "Android with extra steps."

## What it collects

- **`system_summary`**: `os` (always `"chromeos"`), `agent_version`
  (the extension's manifest version), `device_serial`
  (`chrome.enterprise.deviceAttributes.getDeviceSerialNumber`),
  `asset_id` (`getDeviceAssetId`), `annotated_location`
  (`getDeviceAnnotatedLocation`), `directory_device_id`
  (`getDirectoryDeviceId`), and `device_hostname` (`getDeviceHostname`,
  Chrome 82+ only -- omitted on older browsers).
- **`network`**: `mac_address`, `ipv4_address`, `ipv6_address`, all from
  `chrome.enterprise.networkingAttributes.getNetworkDetails` for the
  currently connected network.
- **`hardware`**: `cpu_model`, `cpu_arch`, `cpu_count`
  (`chrome.system.cpu.getInfo`); `memory_total_mb`,
  `memory_available_mb` (`chrome.system.memory.getInfo`); `storage`, an
  array of `{name, type, capacity_mb}` per disk/volume
  (`chrome.system.storage.getInfo`).

Any field that fails to resolve (API unavailable, policy doesn't
allow-list this extension for it, browser too old) is simply omitted
rather than failing the whole report -- see `background.js`'s
`callMethod` helper.

## What it doesn't cover, compared to the native Linux/Windows/macOS/
## Android agents

- **No installed-software inventory.** There's no `chrome.system` or
  `chrome.enterprise` API that lists installed Android/Linux apps or
  extensions on the device; the desktop agents' `installed_software`
  category (and everything downstream of it -- vulnerability
  correlation, software allow/deny rules, shadow-AI detection) has no
  ChromeOS equivalent here.
- **No OS patch/version fact.** Unlike the Android agent's
  `os_version`/`sdk_int` (from `android.os.Build`), there's no public
  extension API that returns the ChromeOS platform version -- Chrome
  deliberately doesn't expose that to extensions. `agent_version` here
  is this extension's own version, not the device's OS version.
  (`navigator.userAgent` does embed a ChromeOS platform version, but
  parsing it was left out rather than reporting a fact this fragile
  with a straight face -- add it in `background.js`'s `systemSummary`
  if you'd rather have a best-effort value than none.)
- **No posture-relevant OS settings** (firewall state, disk encryption,
  screen-lock policy, patch level) -- the Windows/Linux/macOS agents
  read these from OS-level facilities (WMI, `/proc`, `system_profiler`)
  that simply don't exist as extension APIs on ChromeOS. A real
  ChromeOS posture story would likely come from the Admin console's own
  reporting (`chrome.enterprise.reportingPrivate`, a policy-only API not
  available to a regular extension) rather than this surface.
- **Network fact is one interface, not an inventory.** `getNetworkDetails`
  returns the currently *connected* network's MAC/IP, not every
  interface the device has, unlike the Linux agent's fuller network
  fact.

None of this is a bug to fix later so much as it's the real ceiling of
what a Chrome extension -- even an enterprise-policy one -- can see on
ChromeOS; a materially richer ChromeOS agent would need to be a
different kind of integration entirely (e.g. consuming the Admin
console's own device reporting API server-side, not an on-device
extension).

## Setting it up

### 1. Mint an enrollment token

In the Muster web dashboard's **Agents** tab (enter an admin token if
you haven't already), create a new enrollment with platform
**ChromeOS**. This mints a one-time enrollment token tied to that host
name -- copy it now, it's shown only once (see `internal/api/server.go`'s
`handleCreateEnrollment`). The token only ever authorizes fact reports
for that one host name (see `model.Enrollment`'s doc comment on the
server side); if the device is lost or deprovisioned, revoke it from
the Agents tab.

### 2a. Load unpacked, for testing

1. On a Chromebook (or `chrome://extensions` in desktop Chrome, though
   `chrome.enterprise.*` will simply return nothing there -- see
   "What's actually verified" below), open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. **Load unpacked** → select this `agent/chromeos/` directory.
4. The extension has no popup or options UI by design (a background
   service worker only, per this round's brief) -- to push config for
   local testing without a real Admin console, open the extension's
   service worker console from `chrome://extensions` ("service worker"
   link) and run:
   ```js
   // Dev-only stand-in for a pushed enterprise policy -- chrome.storage.managed
   // itself cannot be written from here, so this uses .local, which
   // background.js does NOT read from. For a real end-to-end test you
   // need step 2b (policy-pushed managed storage) or a temporary local
   // edit to getManagedConfig() pointed at chrome.storage.local instead.
   ```
   In practice, meaningfully testing this extension's actual config path
   requires step 2b -- `chrome.storage.managed` is deliberately
   read-only from extension code (see `background.js`'s
   `getManagedConfig` doc comment), so there is no unpacked-only way to
   drive it end-to-end short of temporarily pointing the code at
   `chrome.storage.local` while developing.

### 2b. Force-install via Google Admin console, for real deployment

1. In the [Google Admin console](https://admin.google.com), go to
   **Devices → Chrome → Apps & extensions → Users & browsers**, select
   the org unit these Chromebooks are in.
2. Add this extension by ID (after publishing it to the Chrome Web
   Store, private or public -- an unpublished/unpacked extension cannot
   be force-installed by policy) and set it to **Force install**.
3. Still in the Admin console, configure the extension's **Policy for
   extensions** (managed configuration) for the same org unit, using
   `managed_schema.json`'s three (or four) keys:
   ```json
   {
     "serverUrl": "https://muster.example.com",
     "hostName": "chromebook-eng-042",
     "token": "<the enrollment token from step 1>",
     "reportIntervalMinutes": 30
   }
   ```
   `hostName` must match the enrollment created in step 1 exactly, and
   each device needs its own enrollment token -- there's no
   fleet-wide shared token, same as every other Muster agent.
4. Devices in that org unit pick up the policy on their next policy
   refresh, force-install the extension, and it starts reporting on
   `chrome.alarms` per `reportIntervalMinutes` (default/floor 30
   minutes, capped at 60 -- see `background.js`'s `clampInterval`).

## Why these permissions

- **`enterprise.deviceAttributes`** -- the device serial/asset ID/
  location/directory ID facts. Only resolves real values on a device
  enrolled in Chrome Education/Enterprise Upgrade with this extension
  allow-listed by policy; elsewhere every call resolves to nothing (see
  `callMethod`'s fallback).
- **`enterprise.networkingAttributes`** -- the connected network's MAC/
  IP, gated the same way, plus its own `NetworkingAttributesEnabled`
  policy the admin must turn on.
- **`system.cpu` / `system.memory` / `system.storage`** -- CPU model/
  core count, RAM, and disk capacity; these are regular (non-enterprise)
  `chrome.system.*` APIs, available to any extension that declares them.
- **`storage`** -- required for both `chrome.storage.managed` (reading
  the admin-pushed config) and `chrome.storage.local` (recording
  `lastReportAt`/`lastReportStatus` for debugging).
- **`alarms`** -- `chrome.alarms` is Manifest V3's only mechanism for
  a recurring background job; a service worker itself is not kept alive
  between reports.

No host permissions (`https://*/*` or similar) are declared -- `fetch`
to the configured Muster server URL works from a Manifest V3 service
worker without one as long as the target isn't otherwise blocked by
policy, and declaring a broad host permission this extension doesn't
otherwise need would just be a bigger attack surface for no benefit.

## What's actually verified, and what isn't

This was written in a dev environment with **no ChromeOS device
enrolled in any organization, and no real Google Workspace admin
account** -- so, the same caveat `agent/aws`, `agent/azure`, and
`agent/gcp`'s READMEs already carry for their respective cloud APIs:

- **Verified**: `manifest.json` and `managed_schema.json` are valid
  JSON; `background.js` passes `node --check` (a syntax check only, not
  a Chrome-API behavioral test -- Node has no `chrome.*` globals). The
  extension's structure (MV3 service worker, `chrome.alarms` scheduling,
  `chrome.storage.managed`/`.local` usage, the `POST /api/mobile-report`
  request shape) has been reviewed by hand against Chrome's published
  extension API docs and against `agent/android/MusterClient.kt`'s
  request shape, which this matches field-for-field
  (`{"host", "platform", "facts"}`, `Authorization: Bearer <token>`).
- **Not verified**: this extension has never actually been loaded on a
  real Chromebook, let alone one enrolled in Chrome Enterprise/Education
  Upgrade with `chrome.enterprise.deviceAttributes`/
  `networkingAttributes` allow-listed by policy. Whether
  `getDeviceSerialNumber`/`getNetworkDetails`/etc. actually resolve the
  values this doc claims, whether the Admin console's managed
  configuration UI actually maps `managed_schema.json`'s keys the way
  described, and whether force-install actually works end-to-end are
  all unverified. Treat this as a solid first draft to test against a
  real (or sandboxed) Google Workspace domain and a real managed
  Chromebook before relying on it -- the server side (`POST
  /api/mobile-report` accepting `platform: "chromeos"`) is the one part
  of this round that *has* been verified live, against a running
  Muster server.
