/*******************************************************************************
 * @file         background.js
 * @brief        background.js -- Muster Agent for ChromeOS, a Manifest V3 service worker.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// background.js -- Muster Agent for ChromeOS, a Manifest V3 service
// worker.
//
// Collects the same kind of "cheap, always-available" device facts the
// other agents collect (agent/android/'s DeviceFacts.kt, the desktop
// scripts' /proc or WMI reads) -- here via chrome.enterprise.* and
// chrome.system.* instead -- and POSTs them to Muster's
// POST /api/mobile-report, the exact same JSON ingestion path the
// Android app and iOS Shortcuts flow already use (see internal/api's
// handleMobileReport and agent/android/MusterClient.kt, whose request
// shape this matches field-for-field). Configuration (server URL, host
// name, enrollment token) comes from chrome.storage.managed, i.e.
// pushed by IT via a Chrome policy in the Google Admin console -- see
// managed_schema.json and README.md -- never typed in by the end user.
//
// NOT verified against a real managed Chromebook: chrome.enterprise.*
// only returns real data (and in fact chrome.enterprise.deviceAttributes
// mostly only resolves at all) for an extension force-installed by
// policy on a device enrolled in Chrome Education/Enterprise Upgrade,
// which needs a real Google Workspace admin console this dev
// environment has no access to -- the same "no real account to test
// against" caveat agent/aws, agent/azure, and agent/gcp already carry
// for their cloud APIs. This has been reviewed by hand against Chrome's
// published extension API docs (chrome.enterprise.deviceAttributes,
// chrome.enterprise.networkingAttributes, chrome.system.cpu/memory/
// storage, chrome.storage.managed, chrome.alarms) and loads/runs as an
// unpacked extension (background service worker starts, alarm
// schedules, unconfigured-state warning logs correctly), but the
// enterprise API calls themselves have not been round-tripped against
// a real managed device. Treat it as a solid first draft to test
// against a real (or sandboxed) Google Workspace + managed Chromebook
// before relying on it. See README.md's "What's actually verified"
// section.

const ALARM_NAME = "muster-report";
const DEFAULT_INTERVAL_MINUTES = 30;
const MIN_INTERVAL_MINUTES = 30;
const MAX_INTERVAL_MINUTES = 60;

chrome.runtime.onInstalled.addListener(() => {
  ensureAlarm();
});
chrome.runtime.onStartup.addListener(() => {
  ensureAlarm();
});

// chrome.storage.managed changes when an admin first pushes policy, or
// edits it later -- react immediately (reschedule if the interval
// changed, report right away) rather than waiting up to an hour for
// the next alarm tick.
chrome.storage.onChanged.addListener((_changes, area) => {
  if (area !== "managed") return;
  ensureAlarm();
  reportOnce().catch((err) => console.error("muster: report after config change failed:", err));
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== ALARM_NAME) return;
  reportOnce().catch((err) => console.error("muster: scheduled report failed:", err));
});

async function ensureAlarm() {
  const config = await getManagedConfig();
  const minutes = clampInterval(config.reportIntervalMinutes);
  const existing = await chrome.alarms.get(ALARM_NAME);
  if (existing && Math.round(existing.periodInMinutes) === minutes) {
    return;
  }
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: minutes, delayInMinutes: minutes });
}

function clampInterval(minutes) {
  const n = Number(minutes);
  if (!Number.isFinite(n)) return DEFAULT_INTERVAL_MINUTES;
  return Math.min(MAX_INTERVAL_MINUTES, Math.max(MIN_INTERVAL_MINUTES, n));
}

// getManagedConfig reads the IT-pushed config -- serverUrl/hostName/
// token/reportIntervalMinutes -- from chrome.storage.managed (see
// managed_schema.json). Deliberately never chrome.storage.sync/local
// for these: managed storage is read-only from the extension's own
// side and can only be set via enterprise policy, which is exactly the
// "IT admin pushes config, the end user never configures it by hand"
// model this agent is meant to have -- the ChromeOS counterpart to how
// an enrollment token reaches the Linux/Windows agent scripts via a
// flag an admin fills into the install command, just pushed instead of
// pasted.
function getManagedConfig() {
  return new Promise((resolve) => {
    chrome.storage.managed.get(["serverUrl", "hostName", "token", "reportIntervalMinutes"], (items) => {
      if (chrome.runtime.lastError) {
        console.warn("muster: reading managed storage:", chrome.runtime.lastError.message);
        resolve({});
        return;
      }
      resolve(items || {});
    });
  });
}

async function reportOnce() {
  const config = await getManagedConfig();
  const { serverUrl, hostName, token } = config;
  if (!serverUrl || !hostName || !token) {
    console.warn("muster: not configured (serverUrl/hostName/token missing from managed policy) -- skipping report");
    await chrome.storage.local.set({ lastReportStatus: "not configured" });
    return;
  }

  const facts = await collectFacts();
  const body = JSON.stringify({ host: hostName, platform: "chromeos", facts });
  const url = String(serverUrl).replace(/\/+$/, "") + "/api/mobile-report";

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body,
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(`server returned HTTP ${resp.status}: ${text.slice(0, 300)}`);
    }
    await chrome.storage.local.set({ lastReportAt: Date.now(), lastReportStatus: "ok" });
  } catch (err) {
    await chrome.storage.local.set({ lastReportAt: Date.now(), lastReportStatus: `error: ${err.message || err}` });
    throw err;
  }
}

// collectFacts mirrors the Android agent's category shape
// (system_summary / a status category) -- see agent/android/DeviceFacts.kt
// -- with a third "network" category, since this device's identity
// (serial/asset ID) and its network identity (MAC) come from two
// separate chrome.enterprise.* APIs that don't naturally share a
// category.
async function collectFacts() {
  return {
    system_summary: await systemSummary(),
    network: await networkFacts(),
    hardware: await hardwareFacts(),
  };
}

async function systemSummary() {
  const attrs = chrome.enterprise && chrome.enterprise.deviceAttributes;
  const out = {
    os: "chromeos",
    agent_version: chrome.runtime.getManifest().version,
    device_serial: await callMethod(attrs, "getDeviceSerialNumber"),
    asset_id: await callMethod(attrs, "getDeviceAssetId"),
    annotated_location: await callMethod(attrs, "getDeviceAnnotatedLocation"),
    directory_device_id: await callMethod(attrs, "getDirectoryDeviceId"),
  };
  // getDeviceHostname is a newer addition to the API (Chrome 82+) --
  // guarded separately so an older browser just omits the field
  // instead of every other attribute failing alongside it.
  if (attrs && typeof attrs.getDeviceHostname === "function") {
    out.device_hostname = await callMethod(attrs, "getDeviceHostname");
  }
  return out;
}

async function networkFacts() {
  const attrs = chrome.enterprise && chrome.enterprise.networkingAttributes;
  const details = await callMethod(attrs, "getNetworkDetails");
  if (!details) return {};
  return {
    mac_address: details.macAddress,
    ipv4_address: details.ipv4Address,
    ipv6_address: details.ipv6Address,
  };
}

async function hardwareFacts() {
  const out = {};

  const cpu = await callMethod(chrome.system && chrome.system.cpu, "getInfo");
  if (cpu) {
    out.cpu_model = cpu.modelName;
    out.cpu_arch = cpu.archName;
    out.cpu_count = cpu.numOfProcessors;
  }

  const mem = await callMethod(chrome.system && chrome.system.memory, "getInfo");
  if (mem) {
    out.memory_total_mb = Math.round(mem.capacity / (1024 * 1024));
    out.memory_available_mb = Math.round(mem.availableCapacity / (1024 * 1024));
  }

  const storage = await callMethod(chrome.system && chrome.system.storage, "getInfo");
  if (storage) {
    out.storage = storage.map((d) => ({
      name: d.name,
      type: d.type,
      capacity_mb: Math.round(d.capacity / (1024 * 1024)),
    }));
  }

  return out;
}

// callMethod invokes obj[method](callback) -- the shape every API used
// here has -- and resolves to undefined (never throws) if obj/method
// don't exist or the call errors, so one missing/denied attribute
// (e.g. a policy that doesn't allow-list this extension for
// networkingAttributes) doesn't drop the whole report. Invoked as
// obj[method](...) rather than a detached function reference so
// Chrome's native binding keeps its correct `this`.
function callMethod(obj, method) {
  return new Promise((resolve) => {
    if (!obj || typeof obj[method] !== "function") {
      resolve(undefined);
      return;
    }
    obj[method]((value) => {
      if (chrome.runtime.lastError) {
        resolve(undefined);
        return;
      }
      resolve(value);
    });
  });
}
