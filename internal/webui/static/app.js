/*******************************************************************************
 * @file         app.js
 * @brief        Muster dashboard -- a small hash-routed SPA, no build step, no framework.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Muster dashboard -- a small hash-routed SPA, no build step, no
// framework. Talks to the JSON API in internal/api over fetch().
(() => {
  "use strict";

  const app = document.getElementById("app");
  const searchForm = document.getElementById("search-form");
  const searchField = document.getElementById("search-field");
  const searchContains = document.getElementById("search-contains");
  const searchClear = document.getElementById("search-clear");
  const authToggle = document.getElementById("auth-toggle");
  const authForm = document.getElementById("auth-form");
  const authTokenInput = document.getElementById("auth-token-input");
  const authClear = document.getElementById("auth-clear");
  const authStatus = document.getElementById("auth-status");
  const oauthStatus = document.getElementById("oauth-status");

  // Bearer token, stored per-browser (localStorage survives a reload;
  // it's never sent anywhere but this same origin's own fetch() calls
  // below). Board writes and every GET once -auth-token is on both
  // require this -- see internal/api's requireRole/requireRoleStrict --
  // so without a way to set it here, the dashboard itself couldn't do
  // anything once an operator turned auth on. Wrapped in try/catch:
  // some browser contexts (private windows, blocked site data) throw on
  // storage access, and a missing token should just mean "demo mode,"
  // never a broken page.
  const TOKEN_KEY = "muster_token";
  function getToken() {
    try {
      return localStorage.getItem(TOKEN_KEY) || "";
    } catch {
      return "";
    }
  }
  function setToken(t) {
    try {
      if (t) localStorage.setItem(TOKEN_KEY, t);
      else localStorage.removeItem(TOKEN_KEY);
    } catch {
      // best-effort -- see getToken's comment
    }
  }

  const POLL_MS = 5000;
  // No server-side staleness/rule engine yet (see README "what's next")
  // -- this is purely a display heuristic: a host that hasn't reported
  // in this long shows a STALE badge.
  const STALE_MS = 24 * 60 * 60 * 1000;
  let currentFilter = null; // { field, contains } | null
  let pollTimer = null;
  // Board columns known to the server (GET /api/groups) -- includes
  // both ones an operator explicitly created empty and ones that exist
  // only because some host's group is set to them. Refetched every time
  // the board loads (see showBoard), so a column another browser tab
  // created shows up here too, not just ones this tab typed.
  let knownGroups = [];

  const PLATFORM_ICONS = {
    linux: "img/icon-linux.png",
    windows: "img/icon-windows.png",
  };
  const DEFAULT_ICON = "img/icon-servers.png";

  function platformIcon(platform) {
    return PLATFORM_ICONS[(platform || "").toLowerCase()] || DEFAULT_ICON;
  }

  function timeAgo(iso) {
    if (!iso) return "never";
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return "unknown";
    const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
    if (seconds < 5) return "just now";
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  // Posture score -> a coarse red/yellow/green badge. Thresholds are a
  // display choice, not something the server asserts -- the server just
  // returns the 0-100 score (internal/policy.ComputePosture).
  function postureClass(score) {
    if (score >= 80) return "posture-good";
    if (score >= 50) return "posture-warn";
    return "posture-bad";
  }

  function postureBadge(score) {
    return el("span", { class: `posture-badge ${postureClass(score)}`, text: `${score}/100` });
  }

  function severityClass(sev) {
    return `severity-${(sev || "").toLowerCase()}`;
  }

  const ACRONYMS = { cpu: "CPU", cpus: "CPUs", os: "OS", mb: "MB", mhz: "MHz", id: "ID" };

  function titleCase(key) {
    return key
      .split("_")
      .map((w) => ACRONYMS[w.toLowerCase()] || w.charAt(0).toUpperCase() + w.slice(1))
      .join(" ");
  }

  function formatValue(key, value) {
    if (/_mb$/.test(key)) return `${value} MB`;
    if (/_mhz$/.test(key)) return `${value} MHz`;
    return String(value);
  }

  // A fact whose data is exactly {"count": N, "items": [...]} -- the
  // uniform shape internal/cook.listResult produces for every
  // "N rows of the same thing" category (installed_software,
  // disk_usage, pending_updates, listening_ports, etc. -- see
  // internal/cook/linux_extra.go and windows_extra.go). Rendering it
  // through the generic key/value table below used to hit
  // formatValue -> String(item) for the "items" key, and String() on
  // an array joins it by calling Object.prototype.toString() on every
  // element -- that's where "[object Object],[object Object],..."
  // came from. Detect the shape and render a real sub-table instead.
  function isListShapedFact(data) {
    const keys = Object.keys(data || {});
    return keys.length === 2 && Array.isArray(data.items) && typeof data.count === "number";
  }

  function renderListFact(items) {
    if (!items.length) return el("p", { class: "meta", text: "No entries." });
    const columns = [];
    for (const item of items) {
      for (const k of Object.keys(item || {})) {
        if (!columns.includes(k)) columns.push(k);
      }
    }
    const table = el("table", { class: "fact-table fact-list-table" });
    const head = el("tr");
    for (const col of columns) head.appendChild(el("th", { text: titleCase(col) }));
    table.appendChild(head);
    for (const item of items) {
      const tr = el("tr");
      for (const col of columns) {
        tr.appendChild(el("td", { text: col in item ? formatValue(col, item[col]) : "" }));
      }
      table.appendChild(tr);
    }
    // Cap the on-screen height for long lists -- installed_software on
    // a real host can easily run into the thousands of entries, and
    // without this one fact card turns the whole host-detail page
    // into an endless scroll.
    return el("div", { class: "fact-list-scroll" }, table);
  }

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "text") node.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const child of children) {
      if (child == null) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  async function api(path, opts) {
    const fetchOpts = {};
    const headers = {};
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (opts && opts.method) {
      fetchOpts.method = opts.method;
      if (opts.raw !== undefined) {
        // Scanner CSV exports go up as-is, not wrapped in JSON.
        headers["Content-Type"] = "text/csv";
        fetchOpts.body = opts.raw;
      } else {
        headers["Content-Type"] = "application/json";
        fetchOpts.body = JSON.stringify(opts.body ?? {});
      }
    }
    if (Object.keys(headers).length) fetchOpts.headers = headers;
    const res = await fetch(path, fetchOpts);
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      throw new Error((body && body.error) || `request failed: ${res.status}`);
    }
    return body;
  }

  function isStale(iso) {
    if (!iso) return true;
    const then = new Date(iso).getTime();
    return Number.isNaN(then) || Date.now() - then > STALE_MS;
  }

  function summaryFields(data) {
    // Pick a handful of fields worth showing on the compact card, in a
    // fixed, sensible order -- not every field a fact might have.
    const order = [
      ["distribution", "distribution_version"],
      ["kernel_version"],
      ["cpu_model"],
      ["memory_mb"],
    ];
    const out = [];
    for (const keys of order) {
      for (const k of keys) {
        if (data[k] != null && data[k] !== "") {
          out.push([k, data[k]]);
          break;
        }
      }
    }
    return out;
  }

  function hostCard(host, summary) {
    const dl = el("dl");
    for (const [k, v] of summaryFields(summary || {})) {
      dl.appendChild(el("dt", { text: titleCase(k) }));
      dl.appendChild(el("dd", { text: formatValue(k, v) }));
    }
    return el(
      "a",
      { class: "host-card", href: `#/host/${encodeURIComponent(host.name)}` },
      el(
        "div",
        { class: "host-card-head" },
        el("img", { class: "platform-icon", src: platformIcon(host.platform), alt: "" }),
        el(
          "div",
          {},
          el("div", { class: "host-name", text: host.name }),
          el("div", { class: "host-platform", text: host.platform })
        )
      ),
      dl,
      el("div", { class: "last-cooked", text: `Last reported ${timeAgo(host.last_cooked)}` })
    );
  }

  function emptyState(kind) {
    if (kind === "no-search-results") {
      return el(
        "div",
        { class: "empty-state" },
        el("h2", { text: "No matches" }),
        el("p", { text: "No hosts matched that search. Try a different field or value." })
      );
    }
    return el(
      "div",
      { class: "empty-state" },
      el("img", { src: "img/logotype.png", alt: "Muster" }),
      el("h2", { text: "No hosts reporting yet" }),
      el("p", { text: "Muster is up and waiting for its first packet. Send one with the bundled demo agent:" }),
      el("p", {}, el("code", { text: "go run ./cmd/demoagent -host demo01" })),
      el("p", { text: "or, running in Docker:" }),
      el("p", {}, el("code", { text: "docker compose --profile demo run --rm demoagent" }))
    );
  }

  async function showDashboard() {
    let hosts, facts = new Map();
    try {
      if (currentFilter) {
        const matches = await api(
          `/api/query?category=system_summary&field=${encodeURIComponent(currentFilter.field)}&contains=${encodeURIComponent(currentFilter.contains)}`
        );
        hosts = matches.map((f) => ({ name: f.host }));
        for (const f of matches) facts.set(f.host, f.data);
        // We only have partial Host records from a query match (no
        // platform/last_cooked) -- fetch the real host list once and
        // join on name so cards still render fully.
        const all = await api("/api/hosts");
        const byName = new Map(all.map((h) => [h.name, h]));
        hosts = hosts.map((h) => byName.get(h.name) || h);
      } else {
        hosts = await api("/api/hosts");
      }
    } catch (err) {
      app.replaceChildren(el("div", { class: "error-banner", text: `Couldn't load hosts: ${err.message}` }));
      return;
    }

    if (hosts.length === 0) {
      app.replaceChildren(emptyState(currentFilter ? "no-search-results" : "no-hosts"));
      return;
    }

    // For hosts we didn't already get facts for (the unfiltered path),
    // fetch system_summary in parallel so the card can show real fields.
    const missing = hosts.filter((h) => !facts.has(h.name));
    await Promise.all(
      missing.map(async (h) => {
        try {
          const fact = await api(`/api/hosts/${encodeURIComponent(h.name)}/facts/system_summary`);
          facts.set(h.name, fact.data);
        } catch {
          facts.set(h.name, {});
        }
      })
    );

    const heading = el(
      "div",
      { class: "section-heading" },
      el("h1", { text: currentFilter ? `Search results` : "Hosts" }),
      el("span", { class: "meta", text: `${hosts.length} host${hosts.length === 1 ? "" : "s"}` })
    );
    const grid = el("div", { class: "host-grid" });
    for (const h of hosts.sort((a, b) => a.name.localeCompare(b.name))) {
      grid.appendChild(hostCard(h, facts.get(h.name)));
    }
    app.replaceChildren(heading, grid);
  }

  function groupLabel(g) {
    return g === "" ? "Ungrouped" : g;
  }

  function boardCard(host) {
    const card = el("div", { class: "board-card", draggable: "true" });
    card.addEventListener("dragstart", (e) => {
      e.dataTransfer.setData("text/plain", host.name);
      e.dataTransfer.effectAllowed = "move";
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));

    card.appendChild(
      el(
        "div",
        { class: "board-card-head" },
        el("img", { class: "platform-icon", src: platformIcon(host.platform), alt: "" }),
        el("a", { class: "board-card-name", href: `#/host/${encodeURIComponent(host.name)}`, text: host.name }),
        isStale(host.last_cooked) ? el("span", { class: "stale-badge", text: "STALE" }) : null
      )
    );
    if (host.tags && host.tags.length) {
      const tagsRow = el("div", { class: "tags" });
      for (const t of host.tags) tagsRow.appendChild(el("span", { class: "tag-pill", text: t }));
      card.appendChild(tagsRow);
    }
    card.appendChild(el("div", { class: "last-cooked", text: `Last reported ${timeAgo(host.last_cooked)}` }));
    return card;
  }

  function boardColumn(groupKey, hostsInGroup) {
    const col = el("div", { class: "board-column" });
    const body = el("div", { class: "board-column-body" });
    for (const h of hostsInGroup) body.appendChild(boardCard(h));

    body.addEventListener("dragover", (e) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      col.classList.add("drag-over");
    });
    body.addEventListener("dragleave", () => col.classList.remove("drag-over"));
    body.addEventListener("drop", async (e) => {
      e.preventDefault();
      col.classList.remove("drag-over");
      const name = e.dataTransfer.getData("text/plain");
      if (!name) return;
      try {
        await api(`/api/hosts/${encodeURIComponent(name)}`, { method: "PATCH", body: { group: groupKey } });
      } catch (err) {
        app.prepend(el("div", { class: "error-banner", text: `Couldn't move ${name}: ${err.message}` }));
        return;
      }
      showBoard();
    });

    col.appendChild(
      el(
        "div",
        { class: "board-column-header" },
        el("span", { text: groupLabel(groupKey) }),
        el("span", { class: "count", text: String(hostsInGroup.length) })
      )
    );
    col.appendChild(body);
    return col;
  }

  function addColumnForm() {
    const input = el("input", { type: "text", placeholder: "New group name", autocomplete: "off" });
    const form = el("form", {}, input, el("button", { type: "submit", text: "+ Add column" }));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = input.value.trim();
      if (!name) return;
      try {
        await api("/api/groups", { method: "POST", body: { name } });
      } catch (err) {
        alert(`Couldn't create column: ${err.message}`);
        return;
      }
      showBoard();
    });
    return el("div", { class: "board-add-column" }, form);
  }

  async function showBoard() {
    let hosts;
    try {
      [hosts, knownGroups] = await Promise.all([api("/api/hosts"), api("/api/groups")]);
    } catch (err) {
      app.replaceChildren(el("div", { class: "error-banner", text: `Couldn't load hosts: ${err.message}` }));
      return;
    }

    if (hosts.length === 0 && knownGroups.length === 0) {
      app.replaceChildren(emptyState("no-hosts"));
      return;
    }

    const byGroup = new Map();
    const keys = new Set([""].concat(knownGroups));
    for (const h of hosts) {
      const g = h.group || "";
      keys.add(g);
      if (!byGroup.has(g)) byGroup.set(g, []);
      byGroup.get(g).push(h);
    }
    const ordered = [...keys].sort((a, b) => (a === "" ? -1 : b === "" ? 1 : a.localeCompare(b)));

    const heading = el(
      "div",
      { class: "section-heading" },
      el("h1", { text: "Board" }),
      el("span", { class: "meta", text: `${hosts.length} host${hosts.length === 1 ? "" : "s"} · drag a card to move it` })
    );
    const board = el("div", { class: "board" });
    for (const key of ordered) {
      const groupHosts = (byGroup.get(key) || []).sort((a, b) => a.name.localeCompare(b.name));
      board.appendChild(boardColumn(key, groupHosts));
    }
    board.appendChild(addColumnForm());

    app.replaceChildren(heading, board);
  }

  // Posture and vulnerabilities are fetched best-effort alongside the
  // host itself -- a readonly key that somehow can't reach them (or a
  // transient error) shouldn't block the rest of the page from
  // rendering, so failures here are swallowed to null/empty rather than
  // thrown.
  async function loadPosture(name) {
    try {
      return await api(`/api/hosts/${encodeURIComponent(name)}/posture`);
    } catch {
      return null;
    }
  }

  async function loadVulnerabilities(name) {
    try {
      const payload = await api(`/api/hosts/${encodeURIComponent(name)}/vulnerabilities`);
      return payload.findings || [];
    } catch {
      return [];
    }
  }

  async function loadSoftwareViolations(name) {
    try {
      return await api(`/api/hosts/${encodeURIComponent(name)}/software-violations`);
    } catch {
      return { violations: [], shadow_ai: [] };
    }
  }

  function postureCard(posture) {
    const body = el("div", { class: "posture-body" }, postureBadge(posture.score));
    if (posture.findings && posture.findings.length) {
      const list = el("ul", { class: "posture-findings" });
      for (const f of posture.findings) list.appendChild(el("li", { text: f }));
      body.appendChild(list);
    } else {
      body.appendChild(el("p", { class: "posture-clean", text: "No posture issues observed." }));
    }
    return el("div", { class: "fact-card" }, el("h2", { text: "Compliance posture" }), body);
  }

  function vulnerabilitiesCard(findings) {
    if (!findings.length) {
      return el(
        "div",
        { class: "fact-card" },
        el("h2", { text: "Vulnerabilities" }),
        el("p", { text: "No known-vulnerable packages found against Muster's curated dataset (not a live CVE feed)." })
      );
    }
    const list = el("ul", { class: "vuln-list" });
    for (const f of findings) {
      list.appendChild(
        el(
          "li",
          { class: "vuln-row" },
          el("span", { class: `severity-pill ${severityClass(f.severity)}`, text: f.severity }),
          el(
            "span",
            { class: "vuln-detail" },
            el("strong", { text: f.installed_version ? `${f.package} ${f.installed_version}` : f.package }),
            f.cve ? ` ${f.cve}` : "",
            f.source ? el("span", { class: "meta", text: ` (imported from ${f.source})` }) : "",
            f.description ? `: ${f.description}` : ""
          )
        )
      );
    }
    return el("div", { class: "fact-card" }, el("h2", { text: `Vulnerabilities (${findings.length})` }), list);
  }

  // softwareViolationsCard renders the generic (operator-configured
  // allow/deny rule) violations -- deliberately separate from
  // shadowAICard below so the two never get lumped into one list, even
  // though both come back from the same /software-violations call.
  function softwareViolationsCard(violations) {
    if (!violations.length) {
      return el(
        "div", { class: "fact-card" },
        el("h2", { text: "Software violations" }),
        el("p", { text: "No allow/deny software rule violations." })
      );
    }
    const list = el("ul", { class: "vuln-list" });
    for (const v of violations) {
      list.appendChild(
        el(
          "li", { class: "vuln-row" },
          el("span", { class: "severity-pill severity-medium", text: v.kind }),
          el("span", { class: "vuln-detail" }, el("strong", { text: `${v.package} ${v.version}` }), ` — rule: ${v.rule}` )
        )
      );
    }
    return el("div", { class: "fact-card" }, el("h2", { text: `Software violations (${violations.length})` }), list);
  }

  // shadowAICard is its own labeled section -- see internal/allowlist's
  // ShadowAIPatterns: a built-in, pre-seeded ruleset flagging known AI
  // desktop apps, CLI tools, and browser extensions, distinct from the
  // operator-configured allow/deny rules softwareViolationsCard shows.
  // browserExtensionsCard lists every extension the agent found on the
  // host, riskiest first, with the reasons internal/browserext gave --
  // never a level without a why.
  function browserExtensionsCard(data) {
    if (!data || !data.reported) {
      return el("div", { class: "fact-card" }, el("h2", { text: "Browser extensions" }),
        el("p", { class: "meta", text: "Not reported -- this host's agent predates browser-extension collection, or no Chromium-family browser profile was found." }));
    }
    if (!data.extensions.length) {
      return el("div", { class: "fact-card" }, el("h2", { text: "Browser extensions" }), el("p", { text: "No browser extensions installed." }));
    }
    const list = el("ul", { class: "vuln-list" });
    for (const e of data.extensions) {
      const pillCls = e.level === "high" ? "severity-critical" : e.level === "medium" ? "severity-medium" : "severity-low";
      const li = el("li", { class: "vuln-row" },
        el("span", { class: `severity-pill ${pillCls}`, text: e.level }),
        el("span", { class: "vuln-detail" },
          el("strong", { text: `${e.name} ${e.version || ""}` }),
          ` — ${e.browser}, profile ${e.profile}${e.from_web_store ? "" : ", sideloaded"}`,
          e.reasons && e.reasons.length ? el("ul", { class: "posture-findings" }, ...e.reasons.map((r) => el("li", { text: r }))) : null));
      list.appendChild(li);
    }
    return el("div", { class: "fact-card" },
      el("h2", { text: `Browser extensions (${data.total}, ${data.risky} risky)` }),
      el("p", { class: "meta", text: "Scored on broad site access, sensitive permissions (request interception, cookies, native messaging, clipboard, debugger), sideloading, deprecated manifest version, and a curated deny-list; a curated trusted list keeps ad blockers and password managers from scoring high for permissions they need. See internal/browserext." }),
      list);
  }

  // frameworksCard shows every built-in compliance framework's verdict
  // for one host -- score plus the failing checks by name, so the three
  // mappings (Baseline, HIPAA, NIST) can be compared side by side.
  function frameworksCard(results) {
    const blocks = results.map((r) => {
      const failed = (r.checks || []).filter((c) => !c.pass);
      return el("div", { class: "framework-block" },
        el("div", { class: "framework-head" }, complianceScoreBadge(r.score), el("strong", { text: r.framework })),
        failed.length
          ? el("ul", { class: "posture-findings" }, ...failed.map((c) => el("li", { text: `${c.id}: ${c.detail || c.description}` })))
          : el("p", { class: "posture-clean", text: "All checks pass." }));
    });
    return el("div", { class: "fact-card" }, el("h2", { text: "Compliance frameworks" }), ...blocks);
  }

  // baselineCard is the host page's golden-baseline section: capture,
  // recapture, clear, and the drift list (see internal/baseline).
  function baselineCard(host, rep, reload) {
    const msg = el("span", { class: "save-msg" });
    const noteInput = el("input", { type: "text", placeholder: "note, e.g. golden image 2026-09" });
    const captureBtn = el("button", { type: "button", text: rep.has_baseline ? "Recapture now" : "Capture baseline now" });
    captureBtn.addEventListener("click", async () => {
      msg.textContent = "Capturing…";
      try { await api(`/api/hosts/${encodeURIComponent(host)}/baseline`, { method: "POST", body: { note: noteInput.value.trim() } }); msg.textContent = "Captured"; reload(); }
      catch (err) { msg.textContent = `Error: ${err.message}`; }
    });
    const row = el("div", { class: "editor-row" }, noteInput, captureBtn);
    if (rep.has_baseline) {
      const clearBtn = el("button", { type: "button", class: "ghost", text: "Clear" });
      clearBtn.addEventListener("click", async () => {
        if (!confirm(`Clear the golden baseline for ${host}?`)) return;
        try { await api(`/api/hosts/${encodeURIComponent(host)}/baseline`, { method: "DELETE" }); reload(); }
        catch (err) { msg.textContent = `Error: ${err.message}`; }
      });
      row.appendChild(clearBtn);
    }
    row.appendChild(msg);

    const body = [];
    if (!rep.has_baseline) {
      body.push(el("p", { text: "No golden baseline captured for this host. Capture one when the host is in a known-good state, and every later report is compared against it." }));
    } else {
      body.push(el("p", { class: "meta", text: `Captured ${timeAgo(rep.captured_at)} by ${rep.captured_by}${rep.note ? ` -- ${rep.note}` : ""} · ${rep.categories.length} categories` }));
      if (!rep.drifted) {
        body.push(el("p", { class: "posture-clean", text: "No drift -- the host matches its baseline." }));
      } else {
        const list = el("ul", { class: "changes-list" });
        for (const d of rep.drift) {
          let detail;
          if (d.action === "add") detail = `${d.field} added${d.new_value ? ` (${d.new_value})` : ""}`;
          else if (d.action === "remove") detail = `${d.field} removed${d.old_value ? ` (was ${d.old_value})` : ""}`;
          else detail = `${d.field}: ${d.old_value} → ${d.new_value}`;
          list.appendChild(el("li", { class: "change-row" },
            el("span", { class: `change-action ${d.action}`, text: d.action }),
            el("span", { class: "change-detail", text: `${detail} (${d.category.replace(/_/g, " ")})` })));
        }
        body.push(el("p", { class: "meta", text: `${rep.drift.length} difference(s) from baseline:` }), list);
      }
    }
    return el("div", { class: "fact-card" },
      el("h2", { text: rep.has_baseline ? (rep.drifted ? `Golden baseline -- DRIFTED (${rep.drift.length})` : "Golden baseline -- in sync") : "Golden baseline" }),
      ...body, row);
  }

  // driftCard is the Fleet tab's config-drift rollup from GET /api/drift.
  async function driftCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Config drift" }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const d = await api("/api/drift");
      const rows = d.hosts.map((h) => el("li", { class: "policy-row" },
        el("a", { href: `#/host/${encodeURIComponent(h.host)}`, class: "policy-name", text: h.host }),
        el("span", { class: `posture-badge ${h.drifted ? "posture-bad" : "posture-good"}`, text: h.drifted ? `${h.drift.length} drifted` : "in sync" }),
        el("span", { class: "change-time", text: `baseline ${timeAgo(h.captured_at)}${h.note ? ` -- ${h.note}` : ""}` })));
      card.replaceChildren(el("h2", { text: `Config drift (${d.drifted} of ${d.baselined} baselined hosts drifted)` }),
        el("p", { class: "meta", text: "Hosts with a captured golden baseline, compared against their facts right now. Capture a baseline from a host's page." }),
        rows.length ? el("ul", { class: "policy-list" }, ...rows) : el("p", { text: "No baselines captured yet." }));
    } catch (err) {
      card.replaceChildren(el("h2", { text: "Config drift" }), el("p", { text: `Couldn't load drift: ${err.message}` }));
    }
    return card;
  }

  // lifecycleCard is the host page's OS support + certificate expiry
  // section, with the SBOM download alongside (all three answer "what
  // is on this box and how long is it good for").
  function lifecycleCard(host, d) {
    const osCls = d.os.state === "eol" ? "posture-bad" : d.os.state === "ending-soon" ? "posture-warn" : d.os.state === "supported" ? "posture-good" : "";
    const osRow = el("div", { class: "posture-body" },
      el("span", { class: `posture-badge ${osCls}`, text: d.os.state === "unknown" ? "OS lifecycle unknown" : d.os.state.replace("-", " ") }),
      el("span", { class: "meta", text: " " + d.os.detail }));
    const certList = el("ul", { class: "vuln-list" });
    for (const c of d.certificates) {
      const cls = c.state === "expired" ? "severity-critical" : c.state === "expiring" ? "severity-medium" : c.state === "ok" ? "severity-low" : "severity-low";
      certList.appendChild(el("li", { class: "vuln-row" },
        el("span", { class: `severity-pill ${cls}`, text: c.state }),
        el("span", { class: "vuln-detail" }, el("strong", { text: c.subject || c.id }), ` — ${c.detail}`, el("div", { class: "meta", text: `issuer ${c.issuer || "?"} · ${c.id}` }))));
    }
    const certs = !d.certs_reported
      ? el("p", { class: "meta", text: "No certificate inventory reported -- the agent looks in Let's Encrypt, nginx/apache/haproxy and the RHEL/Debian cert dirs on Linux and macOS, and the machine Personal store on Windows." })
      : d.certificates.length ? certList : el("p", { text: "No server certificates found." });
    const sbomBtn = el("button", { type: "button", text: "Download SBOM (CycloneDX)" });
    const msg = el("span", { class: "save-msg" });
    sbomBtn.addEventListener("click", async () => {
      msg.textContent = "Preparing…";
      try { await downloadWithToken(`/api/hosts/${encodeURIComponent(host)}/sbom`, `${host}.cdx.json`); msg.textContent = ""; }
      catch (err) { msg.textContent = `Error: ${err.message}`; }
    });
    return el("div", { class: "fact-card" },
      el("h2", { text: `OS lifecycle & certificates${d.certificate_issues ? ` (${d.certificate_issues} certificate issue${d.certificate_issues === 1 ? "" : "s"})` : ""}` }),
      osRow,
      el("h3", { class: "subhead", text: "Server certificates" }), certs,
      el("div", { class: "editor-row" }, el("label", { text: "Software bill of materials" }), sbomBtn, msg));
  }

  // sprawlCard is the Compliance tab's license / SaaS sprawl rollup.
  async function sprawlCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "License & SaaS sprawl" }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const d = await api("/api/software/sprawl");
      const stats = el("div", { class: "stat-grid" },
        statCard("Licensed seats deployed", d.licensed_seats),
        statCard("Products found", d.installs.length),
        statCard("Hosts with catalog matches", `${d.hosts_covered} / ${d.total_hosts}`),
        statCard("Overlapping categories", d.overlaps.length, d.overlaps.length > 0 ? "stat-warn" : ""));
      const rows = d.installs.map((i) => el("li", { class: "policy-row" },
        el("span", { class: "policy-name", text: i.product }),
        el("span", { class: "tag-pill", text: i.category }),
        el("span", { class: "policy-condition", text: `${i.seats} seat${i.seats === 1 ? "" : "s"}${i.licensed ? " (licensed)" : " (free)"}: ${i.hosts.join(", ")}` })));
      const overlaps = d.overlaps.map((o) => el("li", { class: "policy-row" },
        el("span", { class: "policy-name", text: o.category }),
        el("span", { class: "policy-condition", text: `${o.products.length} products doing the same job: ${o.products.join(", ")} (${o.seats} seats total)` })));
      card.replaceChildren(el("h2", { text: "License & SaaS sprawl" }),
        el("p", { class: "meta", text: "The same installed-software inventory the security checks use, asked the finance question: which commercial and SaaS desktop products are deployed, how many seats, and where more than one tool does the same job. Catalog is illustrative (internal/sprawl) -- the seam a real license inventory plugs into." }),
        stats,
        overlaps.length ? el("ul", { class: "policy-list" }, ...overlaps) : null,
        rows.length ? el("ul", { class: "policy-list" }, ...rows) : el("p", { text: "No catalog products found on the fleet." }));
    } catch (err) {
      card.replaceChildren(el("h2", { text: "License & SaaS sprawl" }), el("p", { text: `Couldn't load: ${err.message}` }));
    }
    return card;
  }

  function shadowAICard(findings) {
    if (!findings.length) {
      return el(
        "div", { class: "fact-card shadow-ai-card" },
        el("h2", { text: "Shadow AI" }),
        el("p", { text: "No unauthorized AI tools detected on this host." })
      );
    }
    const list = el("ul", { class: "vuln-list" });
    for (const v of findings) {
      list.appendChild(
        el(
          "li", { class: "vuln-row" },
          el("span", { class: "severity-pill shadow-ai-pill", text: "AI" }),
          el("span", { class: "vuln-detail" }, el("strong", { text: `${v.package} ${v.version}` }), ` — matched: ${v.rule}` )
        )
      );
    }
    return el(
      "div", { class: "fact-card shadow-ai-card" },
      el("h2", { text: `Shadow AI (${findings.length})` }),
      el("p", { class: "meta", text: "Unapproved AI desktop apps, CLI tools, and browser extensions detected in installed software -- see internal/allowlist.ShadowAIPatterns." }),
      list
    );
  }

  async function showHostDetail(name) {
    let payload, posture, findings, softwareViolations;
    try {
      [payload, posture, findings, softwareViolations] = await Promise.all([
        api(`/api/hosts/${encodeURIComponent(name)}`),
        loadPosture(name),
        loadVulnerabilities(name),
        loadSoftwareViolations(name),
      ]);
    } catch (err) {
      app.replaceChildren(el("div", { class: "error-banner", text: `Couldn't load ${name}: ${err.message}` }));
      return;
    }

    const { host, facts } = payload;
    const nodes = [
      el("a", { class: "back-link", href: "#/", text: "← All hosts" }),
      el(
        "div",
        { class: "detail-head" },
        el("img", { class: "platform-icon", src: platformIcon(host.platform), alt: "" }),
        el(
          "div",
          {},
          el(
            "h1",
            {},
            host.name,
            el("span", { class: "badge", text: host.platform }),
            isStale(host.last_cooked) ? el("span", { class: "stale-badge", text: "STALE" }) : null,
            posture ? postureBadge(posture.score) : null
          ),
          el("div", { class: "detail-meta", text: `Last reported ${timeAgo(host.last_cooked)} · first seen ${timeAgo(host.first_seen)}` })
        )
      ),
      groupEditor(host),
      tagEditor(host),
    ];

    if (posture) nodes.push(postureCard(posture));
    const baselineSlot = el("div", {});
    nodes.push(baselineSlot);
    const loadBaseline = () => api(`/api/hosts/${encodeURIComponent(name)}/baseline`).then((rep) => baselineSlot.replaceChildren(baselineCard(name, rep, loadBaseline))).catch(() => {});
    loadBaseline();
    const frameworksSlot = el("div", {});
    nodes.push(frameworksSlot);
    api(`/api/hosts/${encodeURIComponent(name)}/compliance`).then((res) => frameworksSlot.replaceChildren(frameworksCard(Array.isArray(res) ? res : (res.frameworks || [])))).catch(() => {});
    const riskSlot = el("div", {});
    nodes.push(riskSlot);
    api(`/api/hosts/${encodeURIComponent(name)}/risk`).then((r) => riskSlot.replaceChildren(hostRiskCard(r))).catch(() => {});
    // 30-day sparkline, filled in asynchronously so a slow history load
    // never holds up the rest of the page.
    const historySlot = el("div", { class: "fact-card" }, el("h2", { text: "Score history (30 days)" }), el("p", { class: "meta", text: "Loading…" }));
    nodes.push(historySlot);
    api(`/api/hosts/${encodeURIComponent(name)}/history?days=30`).then((h) => {
      if (!h.points || h.points.length < 2) {
        historySlot.replaceChildren(el("h2", { text: "Score history (30 days)" }), el("p", { class: "meta", text: "Not enough history recorded yet -- the evaluator adds a point every run." }));
        return;
      }
      const first = h.points[0], last = h.points[h.points.length - 1];
      historySlot.replaceChildren(
        el("h2", { text: "Score history (30 days)" }),
        el("div", { class: "spark-row" }, sparkline(h.points, HOST_TREND_SERIES),
          el("span", { class: "meta", text: `posture ${first.posture} → ${last.posture}, compliance ${first.compliance} → ${last.compliance}, ${h.points.length} points` }))
      );
    }).catch((err) => historySlot.replaceChildren(el("h2", { text: "Score history" }), el("p", { class: "meta", text: `Couldn't load: ${err.message}` })));
    nodes.push(vulnerabilitiesCard(findings || []));
    nodes.push(softwareViolationsCard((softwareViolations && softwareViolations.violations) || []));
    nodes.push(shadowAICard((softwareViolations && softwareViolations.shadow_ai) || []));
    const lifecycleSlot = el("div", {});
    nodes.push(lifecycleSlot);
    api(`/api/hosts/${encodeURIComponent(name)}/lifecycle`).then((d) => lifecycleSlot.replaceChildren(lifecycleCard(name, d))).catch(() => {});
    const extSlot = el("div", {});
    nodes.push(extSlot);
    api(`/api/hosts/${encodeURIComponent(name)}/browser-extensions`).then((d) => extSlot.replaceChildren(browserExtensionsCard(d))).catch(() => extSlot.replaceChildren(browserExtensionsCard(null)));

    if (!facts || facts.length === 0) {
      nodes.push(el("p", { text: "No facts recorded for this host yet." }));
    }
    for (const fact of facts || []) {
      let body;
      if (isListShapedFact(fact.data)) {
        body = el(
          "div",
          {},
          el("p", { class: "meta", text: `${fact.data.count} entries` }),
          renderListFact(fact.data.items)
        );
      } else {
        const table = el("table", { class: "fact-table" });
        for (const [k, v] of Object.entries(fact.data).sort(([a], [b]) => a.localeCompare(b))) {
          const tr = el("tr");
          tr.appendChild(el("td", { text: titleCase(k) }));
          tr.appendChild(el("td", { text: formatValue(k, v) }));
          table.appendChild(tr);
        }
        body = table;
      }
      nodes.push(el("div", { class: "fact-card" }, el("h2", { text: fact.category.replace(/_/g, " ") }), body));
    }

    nodes.push(await loadChanges(name));

    app.replaceChildren(...nodes);
  }

  function groupEditor(host) {
    const input = el("input", { type: "text", value: host.group || "", placeholder: "e.g. prod" });
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "Board group" }),
      input,
      el("button", { type: "submit", text: "Save" }),
      msg
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.textContent = "Saving…";
      try {
        await api(`/api/hosts/${encodeURIComponent(host.name)}`, { method: "PATCH", body: { group: input.value.trim() } });
        msg.textContent = "Saved";
        setTimeout(() => { msg.textContent = ""; }, 1500);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return form;
  }

  function tagEditor(host) {
    let tags = (host.tags || []).slice();
    const pillsWrap = el("span", {});
    const input = el("input", { type: "text", placeholder: "new tag" });
    const addBtn = el("button", { type: "button", text: "+ Add" });
    const msg = el("span", { class: "save-msg" });

    async function save() {
      msg.textContent = "Saving…";
      try {
        await api(`/api/hosts/${encodeURIComponent(host.name)}`, { method: "PATCH", body: { tags } });
        msg.textContent = "Saved";
        setTimeout(() => { msg.textContent = ""; }, 1500);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    }

    function renderPills() {
      pillsWrap.replaceChildren(
        ...tags.map((t) => {
          const removeBtn = el("button", { type: "button", text: "×", title: `Remove ${t}` });
          const pill = el("span", { class: "tag-pill removable" }, t, removeBtn);
          removeBtn.addEventListener("click", async () => {
            tags = tags.filter((x) => x !== t);
            renderPills();
            await save();
          });
          return pill;
        })
      );
    }
    renderPills();

    async function addTag() {
      const v = input.value.trim();
      if (!v || tags.includes(v)) {
        input.value = "";
        return;
      }
      tags.push(v);
      input.value = "";
      renderPills();
      await save();
    }
    addBtn.addEventListener("click", addTag);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        addTag();
      }
    });

    return el("div", { class: "editor-row" }, el("label", { text: "Tags" }), pillsWrap, input, addBtn, msg);
  }

  function changeRow(c) {
    let detail;
    if (c.action === "add") detail = `${titleCase(c.field)} set to ${c.new_value}`;
    else if (c.action === "remove") detail = `${titleCase(c.field)} removed (was ${c.old_value})`;
    else detail = `${titleCase(c.field)}: ${c.old_value} → ${c.new_value}`;
    return el(
      "li",
      { class: "change-row" },
      el("span", { class: `change-action ${c.action}`, text: c.action }),
      el("span", { class: "change-detail", text: `${detail} (${c.category.replace(/_/g, " ")})` }),
      el("span", { class: "change-time", text: timeAgo(c.changed_at) })
    );
  }

  async function loadChanges(name) {
    let changes;
    try {
      changes = await api(`/api/hosts/${encodeURIComponent(name)}/changes?limit=25`);
    } catch (err) {
      return el("div", { class: "error-banner", text: `Couldn't load change history: ${err.message}` });
    }
    if (!changes.length) {
      return el(
        "div",
        { class: "fact-card" },
        el("h2", { text: "Recent changes" }),
        el("p", { text: "No changes recorded yet -- this host has only reported once, or every report since has matched the last one." })
      );
    }
    const list = el("ul", { class: "changes-list" });
    for (const c of changes) list.appendChild(changeRow(c));
    return el("div", { class: "fact-card" }, el("h2", { text: "Recent changes" }), list);
  }

  // ruleSummary renders one policy rule's condition in plain language --
  // mirrors internal/evaluator.violates' fixed switch over Kind, so a
  // reader never sees a rule described in terms this UI doesn't also
  // enforce.
  function ruleSummary(rule) {
    switch (rule.kind) {
      case "stale":
        return "host hasn't reported in 24h";
      case "score_below":
        return `posture score below ${rule.threshold}`;
      case "category_missing":
        return `category "${rule.category}" never reported`;
      case "vulnerabilities_found":
        return "any known-vulnerable package found";
      default:
        return rule.kind;
    }
  }

  function policyRuleForm(onCreated) {
    const nameInput = el("input", { type: "text", placeholder: "rule name" });
    const kindSelect = el(
      "select", {},
      el("option", { value: "stale", text: "Stale (hasn't reported in 24h)" }),
      el("option", { value: "score_below", text: "Posture score below..." }),
      el("option", { value: "category_missing", text: "Category never reported" }),
      el("option", { value: "vulnerabilities_found", text: "Any known-vulnerable package" })
    );
    const thresholdInput = el("input", { type: "number", placeholder: "threshold % (score_below only)", min: "0", max: "100" });
    const categoryInput = el("input", { type: "text", placeholder: "category (category_missing only)" });
    const groupInput = el("input", { type: "text", placeholder: "group (optional)" });
    const remediateSelect = el(
      "select", {},
      el("option", { value: "", text: "No auto-remediation" }),
      el("option", { value: "restart-service", text: "Auto: restart-service" }),
      el("option", { value: "apply-updates", text: "Auto: apply-updates" })
    );
    const remediateArgInput = el("input", { type: "text", placeholder: "service name (restart-service only)" });
    const approvalBox = el("input", { type: "checkbox", title: "Park the auto-remediation as a pending approval instead of queuing it immediately" });
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "New policy rule" }),
      nameInput, kindSelect, thresholdInput, categoryInput, groupInput, remediateSelect, remediateArgInput,
      el("label", { text: "Require approval" }), approvalBox,
      el("button", { type: "submit", text: "Create" }),
      msg
    );

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = nameInput.value.trim();
      if (!name) return;
      msg.textContent = "Creating...";
      try {
        await api("/api/policies", {
          method: "POST",
          body: {
            name,
            kind: kindSelect.value,
            threshold: thresholdInput.value ? Number(thresholdInput.value) : 0,
            category: categoryInput.value.trim(),
            group: groupInput.value.trim(),
            auto_remediate: remediateSelect.value,
            auto_remediate_arg: remediateArgInput.value.trim(),
            require_approval: approvalBox.checked,
          },
        });
        msg.textContent = "";
        nameInput.value = "";
        thresholdInput.value = "";
        categoryInput.value = "";
        groupInput.value = "";
        remediateArgInput.value = "";
        remediateSelect.value = "";
        onCreated();
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });

    // "Describe it" row: plain English -> POST /api/ask/draft-policy ->
    // the fields above get filled in for review. The draft is never
    // created on its own; Create is still the operator's click.
    const descInput = el("input", { type: "text", class: "wide", placeholder: "e.g. flag prod hosts below 80 posture and restart nginx after I approve" });
    const draftBtn = el("button", { type: "button", text: "Draft with Ask Muster" });
    const draftMsg = el("span", { class: "save-msg" });
    draftBtn.addEventListener("click", async () => {
      const description = descInput.value.trim();
      if (!description) return;
      draftMsg.textContent = "Drafting…";
      try {
        const r = await api("/api/ask/draft-policy", { method: "POST", body: { description } });
        const d = r.draft;
        nameInput.value = d.name || "";
        kindSelect.value = d.kind || "stale";
        thresholdInput.value = d.threshold ? String(d.threshold) : "";
        categoryInput.value = d.category || "";
        groupInput.value = d.group || "";
        remediateSelect.value = d.auto_remediate || "";
        remediateArgInput.value = d.auto_remediate_arg || "";
        approvalBox.checked = !!d.require_approval;
        draftMsg.textContent = `${d.source === "heuristic" ? "Drafted by keyword rules (Ask Muster not configured)" : "Drafted by Ask Muster"}: ${d.explanation}${r.validation_error ? ` -- needs a fix: ${r.validation_error}` : ""}. Review the fields, then Create.`;
      } catch (err) {
        draftMsg.textContent = `Error: ${err.message}`;
      }
    });
    const draftRow = el("div", { class: "editor-row" }, el("label", { text: "Or describe it" }), descInput, draftBtn, draftMsg);
    const wrapper = el("div", {}, draftRow, form);
    return wrapper;
  }

  function policyRow(rule, onDelete) {
    const parts = [
      el("span", { class: "policy-name", text: rule.name }),
      el("span", { class: "policy-scope", text: rule.group ? `group: ${rule.group}` : "all hosts" }),
      el("span", { class: "policy-condition", text: ruleSummary(rule) }),
    ];
    if (rule.auto_remediate) {
      parts.push(el("span", { class: "tag-pill", text: `${rule.require_approval ? "proposes" : "auto"}: ${rule.auto_remediate}${rule.auto_remediate_arg ? " " + rule.auto_remediate_arg : ""}${rule.require_approval ? " (needs approval)" : ""}` }));
    }
    if (onDelete) {
      const delBtn = el("button", { type: "button", class: "ghost", text: "Delete" });
      delBtn.addEventListener("click", () => onDelete(rule));
      parts.push(delBtn);
    }
    return el("li", { class: "policy-row" }, ...parts);
  }

  function discoveredAssetRow(asset, onDelete) {
    const delBtn = el("button", { type: "button", class: "ghost", text: "Dismiss" });
    delBtn.addEventListener("click", () => onDelete(asset));
    return el(
      "li",
      { class: "policy-row" },
      el("span", { class: "policy-name", text: asset.address }),
      el("span", { class: `posture-badge ${asset.known ? "posture-good" : "posture-warn"}`, text: asset.known ? "known" : "unknown" }),
      el("span", { class: "policy-condition", text: (asset.open_ports && asset.open_ports.length) ? `ports: ${asset.open_ports.join(", ")}` : "no open ports responded" }),
      el("span", { class: "change-time", text: `last seen ${timeAgo(asset.last_seen_at)}${asset.scanned_cidr ? " -- " + asset.scanned_cidr : ""}` }),
      delBtn
    );
  }

  function auditRow(entry) {
    return el(
      "li",
      { class: "change-row" },
      el("span", { class: "change-action update", text: entry.actor }),
      el("span", { class: "change-detail", text: `${entry.action}${entry.target ? " " + entry.target : ""}${entry.detail ? " — " + entry.detail : ""}` }),
      el("span", { class: "change-time", text: timeAgo(entry.created_at) })
    );
  }

  function statCard(label, value, extraClass) {
    return el("div", { class: `stat-card ${extraClass || ""}` }, el("div", { class: "stat-value", text: String(value) }), el("div", { class: "stat-label", text: label }));
  }

  // svgEl is el() for the SVG namespace -- createElement("svg") would
  // make an HTML element that renders nothing.
  function svgEl(tag, attrs, ...children) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
    for (const child of children) if (child != null) node.appendChild(child);
    return node;
  }

  // TREND_SERIES is the fixed color order for the score-trend chart:
  // posture always gold, compliance always blue, regardless of which is
  // shown -- color follows the series, never its position.
  const TREND_SERIES = [
    { key: "avg_posture", label: "Avg posture", short: "Posture", color: "#d9a70f" },
    { key: "avg_compliance", label: "Avg compliance", short: "Compliance", color: "#2f6fb3" },
  ];

  // trendChart draws buckets (from GET /api/history) as thin lines on a
  // single 0-100 axis, with a recessive grid, direct end labels, and a
  // hover crosshair + tooltip. Hand-rolled SVG, same no-dependency
  // stance as the rest of this UI.
  function trendChart(buckets, series, opts) {
    const W = (opts && opts.width) || 720, H = (opts && opts.height) || 200;
    const padL = 34, padR = 96, padT = 12, padB = 26;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "trend-chart", role: "img", "aria-label": "Score trend" });
    if (!buckets.length) return svg;
    const x = (i) => padL + (buckets.length === 1 ? plotW / 2 : (i / (buckets.length - 1)) * plotW);
    const y = (v) => padT + plotH - (Math.max(0, Math.min(100, v)) / 100) * plotH;

    for (const g of [0, 25, 50, 75, 100]) {
      svg.appendChild(svgEl("line", { x1: padL, x2: padL + plotW, y1: y(g), y2: y(g), class: "trend-grid" }));
      svg.appendChild(svgEl("text", { x: padL - 6, y: y(g) + 4, class: "trend-axis", "text-anchor": "end", text: String(g) }));
    }
    const fmtDate = (iso) => new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
    const tickEvery = Math.max(1, Math.ceil(buckets.length / 6));
    buckets.forEach((b, i) => {
      if (i % tickEvery === 0 || i === buckets.length - 1) {
        svg.appendChild(svgEl("text", { x: x(i), y: H - 8, class: "trend-axis", "text-anchor": "middle", text: fmtDate(b.at) }));
      }
    });

    const last = buckets[buckets.length - 1];
    // direct end labels, nudged apart when two series end within 14px of
    // each other so neither overprints the other
    const labelYs = series.map((s) => y(last[s.key]));
    const order = labelYs.map((v, i) => i).sort((a, b) => labelYs[a] - labelYs[b]);
    for (let k = 1; k < order.length; k++) {
      const prev = order[k - 1], cur = order[k];
      if (labelYs[cur] - labelYs[prev] < 14) labelYs[cur] = labelYs[prev] + 14;
    }
    series.forEach((s, si) => {
      const d = buckets.map((b, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(b[s.key]).toFixed(1)}`).join(" ");
      svg.appendChild(svgEl("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
      svg.appendChild(svgEl("circle", { cx: x(buckets.length - 1), cy: y(last[s.key]), r: 4, fill: s.color, stroke: "#fff", "stroke-width": 2 }));
      svg.appendChild(svgEl("text", { x: padL + plotW + 10, y: labelYs[si] + 4, class: "trend-label", text: `${s.short || s.label} ${last[s.key]}` }));
    });

    // hover layer: crosshair + tooltip, hit target is the whole plot
    const cross = svgEl("line", { class: "trend-cross", y1: padT, y2: padT + plotH, style: "display:none" });
    const tip = svgEl("g", { class: "trend-tip", style: "display:none" });
    const tipBg = svgEl("rect", { rx: 4, ry: 4, class: "trend-tip-bg" });
    const tipText = svgEl("text", { class: "trend-tip-text" });
    tip.append(tipBg, tipText);
    const hit = svgEl("rect", { x: padL, y: padT, width: plotW, height: plotH, fill: "transparent" });
    hit.addEventListener("mousemove", (e) => {
      const pt = svg.createSVGPoint(); pt.x = e.clientX; pt.y = e.clientY;
      const loc = pt.matrixTransform(svg.getScreenCTM().inverse());
      const i = Math.round(((loc.x - padL) / plotW) * (buckets.length - 1));
      const b = buckets[Math.max(0, Math.min(buckets.length - 1, i))];
      cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i)); cross.style.display = "";
      tipText.replaceChildren();
      const lines = [fmtDate(b.at), ...series.map((s) => `${s.label}: ${b[s.key]}`), `${b.hosts} hosts, ${b.stale_hosts} stale, ${b.hosts_with_vulns} w/ vulns`];
      lines.forEach((t, li) => tipText.appendChild(svgEl("tspan", { x: 0, dy: li === 0 ? 0 : 14, text: t })));
      const tw = Math.max(...lines.map((t) => t.length)) * 6.2 + 12, th = lines.length * 14 + 8;
      const tx = Math.min(x(i) + 10, W - tw - 4), ty = padT + 4;
      tip.setAttribute("transform", `translate(${tx},${ty})`);
      tipBg.setAttribute("width", tw); tipBg.setAttribute("height", th);
      tipText.setAttribute("transform", "translate(6,15)");
      tip.style.display = "";
    });
    hit.addEventListener("mouseleave", () => { cross.style.display = "none"; tip.style.display = "none"; });
    svg.append(cross, tip, hit);
    return svg;
  }

  function trendLegend(series) {
    return el("div", { class: "trend-legend" }, ...series.map((s) =>
      el("span", {}, el("span", { class: "trend-swatch", style: `background:${s.color}` }), s.label)));
  }

  function hoursLabel(h) {
    if (!h) return "n/a";
    if (h < 48) return `${Math.round(h)}h`;
    return `${(h / 24).toFixed(1)}d`;
  }

  // trendCard is the Fleet tab's "Trends" section: the 30-day score
  // chart plus the time-to-remediate rollup next to it, both from
  // GET /api/history. A server with no history yet says so instead of
  // drawing an empty chart.
  async function trendCard(days) {
    const card = el("div", { class: "fact-card" }, el("h2", { text: `Trends (last ${days} days)` }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const h = await api(`/api/history?days=${days}`);
      card.replaceChildren(el("h2", { text: `Trends (last ${h.window_days} days)` }));
      if (!h.buckets.length) {
        card.appendChild(el("p", { text: "No score history recorded yet -- the background evaluator records one point per host each run (every 5 minutes by default), so check back shortly." }));
        return card;
      }
      const m = h.mttr;
      const mttr = el("div", { class: "stat-grid mttr-grid" },
        statCard("Mean time to remediate", hoursLabel(m.mean_hours)),
        statCard("Median", hoursLabel(m.median_hours)),
        statCard("Resolved in window", m.resolved),
        statCard("Still open", m.still_open, m.still_open > 0 ? "stat-warn" : ""),
        statCard("Oldest open", hoursLabel(m.oldest_open_hours), m.oldest_open_hours > 72 ? "stat-warn" : "")
      );
      const first = h.buckets[0], last = h.buckets[h.buckets.length - 1];
      const delta = (k) => { const d = last[k] - first[k]; return `${d >= 0 ? "+" : ""}${d}`; };
      card.append(
        trendLegend(TREND_SERIES),
        trendChart(h.buckets, TREND_SERIES),
        el("p", { class: "meta", text: `Posture ${first.avg_posture} → ${last.avg_posture} (${delta("avg_posture")}), compliance ${first.avg_compliance} → ${last.avg_compliance} (${delta("avg_compliance")}) across ${h.hosts_tracked} tracked hosts. Time to remediate measures how long a host stays below 100% compliance before it's back.` }),
        mttr
      );
      if (m.spans && m.spans.length) {
        const table = el("table", { class: "fact-table" });
        table.appendChild(el("tr", {}, el("th", { text: "Host" }), el("th", { text: "Fell out" }), el("th", { text: "Fixed" }), el("th", { text: "Took" })));
        for (const sp of m.spans.slice(0, 8)) {
          table.appendChild(el("tr", {}, el("td", {}, el("a", { href: `#/host/${encodeURIComponent(sp.host)}`, text: sp.host })),
            el("td", { text: timeAgo(sp.from) }), el("td", { text: timeAgo(sp.to) }), el("td", { text: hoursLabel(sp.duration_hours) })));
        }
        card.appendChild(el("details", {}, el("summary", { text: `Recent remediations (${m.spans.length})` }), table));
      }
    } catch (err) {
      card.replaceChildren(el("h2", { text: "Trends" }), el("p", { text: `Couldn't load score history: ${err.message}` }));
    }
    return card;
  }

  // sparkline is the host-detail miniature of trendChart: posture and
  // compliance over the window, no axes, direct end values only.
  function sparkline(points, series) {
    const W = 420, H = 72;
    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "sparkline", role: "img", "aria-label": "Score history" });
    if (points.length < 2) return svg;
    const x = (i) => 4 + (i / (points.length - 1)) * (W - 110);
    const y = (v) => 4 + (H - 8) - (Math.max(0, Math.min(100, v)) / 100) * (H - 8);
    const last = points[points.length - 1];
    const ys = series.map((s) => y(last[s.key]));
    if (ys.length === 2 && Math.abs(ys[0] - ys[1]) < 12) { const mid = (ys[0] + ys[1]) / 2; ys[0] = mid - 6; ys[1] = mid + 6; }
    series.forEach((s, si) => {
      const d = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p[s.key]).toFixed(1)}`).join(" ");
      svg.appendChild(svgEl("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round" }));
      svg.appendChild(svgEl("text", { x: W - 98, y: ys[si] + 4, class: "trend-label", text: `${s.short} ${last[s.key]}` }));
    });
    return svg;
  }
  const HOST_TREND_SERIES = [
    { key: "posture", label: "Avg posture", short: "Posture", color: "#d9a70f" },
    { key: "compliance", label: "Avg compliance", short: "Compliance", color: "#2f6fb3" },
  ];

  // riskBadge colors a 0-100 risk score (higher = riskier) by level --
  // the mirror image of postureBadge, where higher is better.
  function riskBadge(score, level) {
    const cls = level === "critical" || level === "high" ? "posture-bad" : level === "medium" ? "posture-warn" : "posture-good";
    return el("span", { class: `posture-badge ${cls}`, title: `risk level: ${level}`, text: `${score} ${level}` });
  }

  // riskCard is the Fleet tab's blended-risk section: top hosts as
  // horizontal bars (one hue, length = score, level in text next to it,
  // never color alone) plus the level distribution.
  async function riskCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Risk" }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const r = await api("/api/risk");
      const dist = el("div", { class: "stat-grid" },
        statCard("Average risk", r.average_score),
        statCard("Critical", r.by_level.critical, r.by_level.critical > 0 ? "stat-warn" : ""),
        statCard("High", r.by_level.high, r.by_level.high > 0 ? "stat-warn" : ""),
        statCard("Medium", r.by_level.medium),
        statCard("Low", r.by_level.low));
      const rows = el("ul", { class: "risk-list" });
      for (const h of r.hosts.slice(0, 8)) {
        const tags = [h.criticality !== "medium" ? `criticality ${h.criticality}` : null, h.exposure === "internet" ? "internet-facing" : null].filter(Boolean).join(", ");
        rows.appendChild(el("li", { class: "risk-row" },
          el("a", { href: `#/host/${encodeURIComponent(h.host)}`, class: "policy-name", text: h.host }),
          el("span", { class: "risk-bar-wrap" }, el("span", { class: `risk-bar risk-${h.level}`, style: `width:${Math.max(2, h.score)}%` })),
          riskBadge(h.score, h.level),
          el("span", { class: "change-time", text: tags })));
      }
      card.replaceChildren(el("h2", { text: "Risk (blended, higher is riskier)" }), dist,
        el("p", { class: "meta", text: "Vulnerability severity, posture, staleness, Shadow AI and software-policy violations, weighted by each host's criticality:<level> and exposure:internet tags. Set those from the tag editor on a host's page." }),
        rows);
    } catch (err) {
      card.replaceChildren(el("h2", { text: "Risk" }), el("p", { text: `Couldn't load risk scores: ${err.message}` }));
    }
    return card;
  }

  // benchmarkCard is the Fleet tab's "vs. baseline" comparison. The
  // baseline is illustrative and the card says so -- see internal/benchmark.
  async function benchmarkCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Vs. baseline" }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const b = await api("/api/benchmark");
      const table = el("table", { class: "fact-table bench-table" });
      table.appendChild(el("tr", {}, el("th", { text: "Metric" }), el("th", { text: "This fleet" }), el("th", { text: "Baseline" }), el("th", { text: "" })));
      const fmt = (v, unit) => unit === "hours" ? hoursLabel(v) : unit === "percent" ? `${Math.round(v)}%` : String(Math.round(v));
      for (const m of b.metrics) {
        table.appendChild(el("tr", {},
          el("td", { text: m.label }),
          el("td", { text: fmt(m.fleet, m.unit) }),
          el("td", { text: fmt(m.baseline, m.unit) }),
          el("td", {}, el("span", { class: `bench-delta ${m.better ? "bench-better" : "bench-worse"}`, text: (m.better ? "▲ " : "▼ ") + m.summary }))));
      }
      card.replaceChildren(el("h2", { text: "Vs. baseline" }), table, el("p", { class: "meta", text: `Baseline: ${b.baseline}. Hand-authored reference values for an average mid-sized mixed fleet, not survey data -- the seam a real benchmark dataset would plug into.` }));
    } catch (err) {
      card.replaceChildren(el("h2", { text: "Vs. baseline" }), el("p", { text: `Couldn't load benchmark: ${err.message}` }));
    }
    return card;
  }

  // hostRiskCard is the host page's risk breakdown -- the score plus
  // every factor that fed it, so the number is never a black box.
  function hostRiskCard(r) {
    const trustScore = 100 - r.score;
    const trustLevel = trustScore >= 75 ? "trusted" : trustScore >= 50 ? "conditional" : "untrusted";
    const body = el("div", { class: "posture-body" }, riskBadge(r.score, r.level),
      el("span", { class: `posture-badge ${trustLevel === "trusted" ? "posture-good" : trustLevel === "conditional" ? "posture-warn" : "posture-bad"}`, title: "device trust, as GET /api/trust/{host} reports it to an access gate", text: `trust ${trustScore} ${trustLevel}` }),
      el("span", { class: "meta", text: ` criticality ${r.criticality}, ${r.exposure === "internet" ? "internet-facing" : "internal"} (×${r.multiplier.toFixed(2)})` }));
    if (r.factors && r.factors.length) {
      const list = el("ul", { class: "posture-findings" });
      for (const f of r.factors) list.appendChild(el("li", { text: `${f.name}: +${f.points.toFixed(0)} -- ${f.detail}` }));
      body.appendChild(list);
    } else {
      body.appendChild(el("p", { class: "posture-clean", text: "No risk factors observed." }));
    }
    return el("div", { class: "fact-card" }, el("h2", { text: "Risk score" }), body);
  }

  // downloadWithToken fetches an API path carrying the bearer token (a
  // plain <a href> can't send the Authorization header) and either
  // saves the response as a file or opens it in a new tab.
  async function downloadWithToken(path, filename, openInTab) {
    const headers = {};
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(path, { headers });
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new Error((body && body.error) || `request failed: ${res.status}`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    if (openInTab) {
      window.open(url, "_blank");
    } else {
      const a = el("a", { href: url, download: filename });
      document.body.appendChild(a); a.click(); a.remove();
    }
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  // reportsCard is the Fleet tab's export section: the print-ready
  // executive summary and the four CSV exports (see internal/report).
  function reportsCard() {
    const msg = el("span", { class: "save-msg" });
    const btn = (label, path, filename, openInTab) => {
      const b = el("button", { type: "button", text: label });
      b.addEventListener("click", async () => {
        msg.textContent = "Preparing…";
        try { await downloadWithToken(path, filename, openInTab); msg.textContent = ""; }
        catch (err) { msg.textContent = `Error: ${err.message}`; }
      });
      return b;
    };
    const today = new Date().toISOString().slice(0, 10);
    const summaryOut = el("div", { class: "exec-summary" });
    const summaryBtn = el("button", { type: "button", text: "Executive summary (Ask Muster)" });
    summaryBtn.addEventListener("click", async () => {
      msg.textContent = "Writing…";
      summaryOut.replaceChildren();
      try {
        const r = await api("/api/ask/summary", { method: "POST", body: {} });
        msg.textContent = "";
        const paras = r.summary.text.split(/\n\s*\n/).map((p) => el("p", { text: p }));
        summaryOut.replaceChildren(
          el("p", { class: "meta", text: r.summary.source === "template" ? "Written from a template because Ask Muster isn't configured (set an API key on the Settings page for a model-written summary)." : "Written by Ask Muster from the same data as the executive report; recorded to the audit trail." }),
          ...paras);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return el("div", { class: "fact-card" },
      el("h2", { text: "Reports & exports" }),
      el("div", { class: "editor-row" }, summaryBtn),
      summaryOut,
      el("p", { class: "meta", text: "The executive report opens as a print-ready page (use your browser's Print / Save as PDF). CSV exports carry the same numbers the dashboard shows. Audit export needs an admin credential." }),
      el("div", { class: "editor-row" },
        btn("Executive report", "/api/reports/executive", "", true),
        btn("Compliance CSV", "/api/reports/compliance.csv", `muster-compliance-${today}.csv`),
        btn("Risk CSV", "/api/reports/risk.csv", `muster-risk-${today}.csv`),
        btn("Vulnerabilities CSV", "/api/reports/vulnerabilities.csv", `muster-vulnerabilities-${today}.csv`),
        btn("Audit CSV", "/api/reports/audit.csv", `muster-audit-${today}.csv`),
        msg));
  }

  // approvalsCard is the Fleet tab's change-control queue: every
  // auto-remediation a require_approval rule has proposed, with
  // Approve (queues it) / Reject (drops it) -- see internal/alerts.
  async function approvalsCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Pending approvals" }), el("p", { class: "meta", text: "Loading…" }));
    async function render() {
      try {
        const list = await api("/api/approvals");
        const msg = el("span", { class: "save-msg" });
        const rows = list.map((a) => {
          const approve = el("button", { type: "button", text: "Approve" });
          const reject = el("button", { type: "button", class: "ghost", text: "Reject" });
          const decide = async (d) => {
            msg.textContent = `${d === "approve" ? "Approving" : "Rejecting"}…`;
            try { await api(`/api/approvals/${encodeURIComponent(a.id)}/${d}`, { method: "POST" }); msg.textContent = ""; render(); }
            catch (err) { msg.textContent = `Error: ${err.message}`; }
          };
          approve.addEventListener("click", () => decide("approve"));
          reject.addEventListener("click", () => decide("reject"));
          return el("li", { class: "policy-row" },
            el("a", { href: `#/host/${encodeURIComponent(a.host)}`, class: "policy-name", text: a.host }),
            el("span", { class: "tag-pill", text: `${a.verb}${a.arg ? " " + a.arg : ""}` }),
            el("span", { class: "policy-condition", text: `rule "${a.rule_name}": ${a.reason}` }),
            el("span", { class: "change-time", text: timeAgo(a.created_at) }),
            approve, reject);
        });
        card.replaceChildren(el("h2", { text: `Pending approvals (${list.length})` }),
          el("p", { class: "meta", text: "Remediations proposed by rules marked \"require approval\". Approve queues the action for the host's agent exactly as proposed; reject drops it (the rule will propose again if the violation persists)." }),
          rows.length ? el("ul", { class: "policy-list" }, ...rows) : el("p", { text: "Nothing waiting for approval." }), msg);
      } catch (err) {
        card.replaceChildren(el("h2", { text: "Pending approvals" }), el("p", { text: `Couldn't load approvals: ${err.message}` }));
      }
    }
    await render();
    return card;
  }

  // alertsCard is the Fleet tab's deduplicated "what's wrong right now"
  // list: one row per open (rule, host) violation the evaluator is
  // tracking, however many runs it's persisted, with snooze controls.
  async function alertsCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Open violations" }), el("p", { class: "meta", text: "Loading…" }));
    async function render() {
      try {
        const d = await api("/api/alerts");
        const msg = el("span", { class: "save-msg" });
        const rows = d.violations.map((v) => {
          const snooze = el("button", { type: "button", class: "ghost", text: v.snoozed ? "Unsnooze" : "Snooze 24h" });
          snooze.addEventListener("click", async () => {
            try { await api("/api/alerts/snooze", { method: "POST", body: { key: v.key, hours: v.snoozed ? 0 : 24 } }); render(); }
            catch (err) { msg.textContent = `Error: ${err.message}`; }
          });
          return el("li", { class: "policy-row" },
            el("a", { href: `#/host/${encodeURIComponent(v.host)}`, class: "policy-name", text: v.host }),
            el("span", { class: "policy-condition", text: `${v.rule_name}: ${v.reason}` }),
            el("span", { class: "change-time", text: `open ${timeAgo(v.first_seen)}, seen ${v.occurrences}×${v.snoozed ? `, snoozed until ${new Date(v.snoozed_until).toLocaleString()}` : ""}` }),
            snooze);
        });
        card.replaceChildren(el("h2", { text: `Open violations (${d.open}${d.snoozed ? `, ${d.snoozed} snoozed` : ""})` }),
          el("p", { class: "meta", text: `One row per open finding, however many evaluator runs it has persisted through -- announced to the audit trail and webhooks once when it opens, again every ${d.realert_after_hours}h while open, and once when it clears. Snoozing quiets the re-announcements.` }),
          rows.length ? el("ul", { class: "policy-list" }, ...rows) : el("p", { text: "No open violations." }), msg);
      } catch (err) {
        card.replaceChildren(el("h2", { text: "Open violations" }), el("p", { text: `Couldn't load: ${err.message}` }));
      }
    }
    await render();
    return card;
  }

  // signalsCard is the Fleet tab's behavioral-signals section (UEBA-lite
  // over the audit trail, see internal/ueba). Admin-only server-side;
  // a readonly credential sees the explanation, not an error page.
  async function signalsCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Behavioral signals" }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const d = await api("/api/signals?days=7");
      const rows = d.signals.map((sg) => el("li", { class: "vuln-row" },
        el("span", { class: `severity-pill ${sg.severity === "high" ? "severity-critical" : sg.severity === "medium" ? "severity-medium" : "severity-low"}`, text: sg.severity }),
        el("span", { class: "vuln-detail" }, el("strong", { text: `${sg.kind} — ${sg.actor}` }), ` ${sg.detail}`, el("div", { class: "meta", text: `${timeAgo(sg.at)}${sg.examples && sg.examples.length ? ` · audit ${sg.examples.join(", ")}` : ""}` }))));
      card.replaceChildren(el("h2", { text: `Behavioral signals (${d.signals.length}, last ${d.window_days} days)` }),
        el("p", { class: "meta", text: d.note + ` Scanned ${d.entries_scanned} audit entries.` }),
        rows.length ? el("ul", { class: "vuln-list" }, ...rows) : el("p", { text: "Nothing unusual in operator activity." }));
    } catch (err) {
      card.replaceChildren(el("h2", { text: "Behavioral signals" }), el("p", { text: `Couldn't load signals: ${err.message} -- requires an admin credential.` }));
    }
    return card;
  }

  // scannerImportCard is the Compliance tab's third-party scanner
  // import: a Nessus/Qualys/generic CSV export is read in the browser
  // and POSTed to /api/scanner-import, which matches each finding to a
  // Muster host by name or IP and stores it as a scanner_findings fact.
  function scannerImportCard() {
    const file = el("input", { type: "file", accept: ".csv,text/csv" });
    const format = el("select", {},
      el("option", { value: "nessus", text: "Nessus (.csv export)" }),
      el("option", { value: "qualys", text: "Qualys (.csv export)" }),
      el("option", { value: "generic", text: "Generic (host,cve,severity,title)" }));
    const btn = el("button", { type: "submit", text: "Import" });
    const msg = el("span", { class: "save-msg" });
    const results = el("div", {});
    const form = el("form", { class: "editor-row" }, el("label", { text: "Format" }), format, file, btn, msg);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = file.files && file.files[0];
      if (!f) { msg.textContent = "Pick a CSV export first."; return; }
      msg.textContent = "Importing…";
      try {
        const csv = await f.text();
        const d = await api(`/api/scanner-import?format=${encodeURIComponent(format.value)}`, { method: "POST", raw: csv });
        msg.textContent = "";
        const parts = [el("p", { text: `Parsed ${d.parsed} finding(s) from ${f.name}; matched ${(d.hosts || []).length} host(s).` })];
        if ((d.hosts || []).length) {
          parts.push(el("ul", { class: "posture-findings" }, ...d.hosts.map((h) => el("li", { text: `${h}: ${d.matched[h]} finding(s)` }))));
        }
        const un = Object.keys(d.unmatched || {});
        if (un.length) {
          parts.push(el("p", { class: "meta", text: `${un.length} scanner host(s) not enrolled in Muster (nothing stored for them): ${un.slice(0, 12).join(", ")}` }));
        }
        results.replaceChildren(...parts);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
        results.replaceChildren();
      }
    });
    return el("div", { class: "fact-card" }, el("h2", { text: "Import scanner findings" }),
      el("p", { class: "meta", text: "Muster's own vulnerability view matches installed package versions against a static dataset. A real program already has a scanner; this imports its CSV export so those findings land on the same host records and flow into compliance, risk, and the summary. Findings are matched by hostname, short hostname, or an IPv4 address from the host's network_interfaces fact. Admin only." }),
      form, results);
  }

  // breachCard is the Compliance tab's Have I Been Pwned lookup.
  function breachCard() {
    const input = el("input", { type: "text", placeholder: "your-company.com" });
    const btn = el("button", { type: "submit", text: "Check" });
    const msg = el("span", { class: "save-msg" });
    const results = el("div", {});
    const form = el("form", { class: "editor-row" }, el("label", { text: "Domain" }), input, btn, msg);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const domain = input.value.trim();
      if (!domain) return;
      msg.textContent = "Checking…";
      try {
        const d = await api(`/api/breaches?domain=${encodeURIComponent(domain)}`);
        msg.textContent = "";
        const parts = [el("p", { class: "meta", text: d.mode })];
        if (d.account_lookup_configured) {
          const aliases = Object.entries(d.exposed_aliases || {});
          parts.push(el("p", { text: `${d.exposed_count} account(s) on ${domain} appear in known breaches.` }));
          if (aliases.length) parts.push(el("ul", { class: "posture-findings" }, ...aliases.slice(0, 50).map(([a, bs]) => el("li", { text: `${a}@${domain}: ${bs.join(", ")}` }))));
        }
        const bs = d.breaches_of_domain || [];
        parts.push(el("p", { text: bs.length ? `${bs.length} known breach(es) of ${domain} itself:` : `No known breaches of ${domain} itself.` }));
        if (bs.length) parts.push(el("ul", { class: "posture-findings" }, ...bs.map((b) => el("li", { text: `${b.Title} (${b.BreachDate}): ${b.PwnCount.toLocaleString()} accounts, ${(b.DataClasses || []).slice(0, 4).join(", ")}` }))));
        results.replaceChildren(...parts);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return el("div", { class: "fact-card" }, el("h2", { text: "Breach exposure (Have I Been Pwned)" }),
      el("p", { class: "meta", text: "With an HIBP API key (-hibp-api-key), lists every account on your domain found in a known breach; without one, the public list of breaches of the domain itself. Admin only." }),
      form, results);
  }

  // graphCard draws GET /api/graph: hubs (subnets / groups) with their
  // members around them, managed hosts colored by risk level, discovered
  // assets dashed, and a "this discovered address is that host" edge
  // where discovery matched an enrolled host.
  async function graphCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Network & assets" }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const g = await api("/api/graph");
      const svg = svgEl("svg", { viewBox: `0 0 ${g.width} ${g.height}`, class: "asset-graph", role: "img", "aria-label": "Network and asset map" });
      const byID = {};
      for (const n of g.nodes) byID[n.id] = n;
      for (const e of g.edges) {
        const a = byID[e.from], b = byID[e.to];
        if (!a || !b) continue;
        svg.appendChild(svgEl("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: `graph-edge graph-edge-${e.kind}` }));
      }
      const levelColor = { low: "#6b7278", medium: "#d9a70f", high: "#c0392b", critical: "#c0392b", unknown: "#9aa3a8", known: "#2f6fb3" };
      for (const n of g.nodes) {
        const grp = svgEl("g", { class: `graph-node graph-node-${n.kind}`, transform: `translate(${n.x},${n.y})` });
        if (n.kind === "hub") {
          grp.appendChild(svgEl("circle", { r: 32, class: "graph-hub" }));
          grp.appendChild(svgEl("text", { y: 3, class: "graph-hub-label", "text-anchor": "middle", text: n.label }));
          grp.appendChild(svgEl("text", { y: 46, class: "graph-sub", "text-anchor": "middle", text: `${n.sub} · ${n.members}` }));
        } else if (n.kind === "asset") {
          grp.appendChild(svgEl("rect", { x: -9, y: -9, width: 18, height: 18, rx: 3, class: "graph-asset", stroke: levelColor[n.level] || "#9aa3a8" }));
          grp.appendChild(svgEl("text", { y: 22, class: "graph-label", "text-anchor": "middle", text: n.label }));
          if (n.sub) grp.appendChild(svgEl("text", { y: 34, class: "graph-sub", "text-anchor": "middle", text: n.sub }));
        } else {
          grp.appendChild(svgEl("circle", { r: 9, fill: levelColor[n.level] || "#6b7278", stroke: "#fff", "stroke-width": 2 }));
          grp.appendChild(svgEl("text", { y: 22, class: "graph-label", "text-anchor": "middle", text: n.label }));
          if (n.sub) grp.appendChild(svgEl("text", { y: 34, class: "graph-sub", "text-anchor": "middle", text: n.sub }));
          if (n.href) grp.addEventListener("click", () => { location.hash = n.href; });
          grp.appendChild(svgEl("title", { text: `${n.label}: risk ${n.score} (${n.level})` }));
        }
        svg.appendChild(grp);
      }
      const hosts = g.nodes.filter((n) => n.kind === "host").length, assets = g.nodes.filter((n) => n.kind === "asset").length, hubs = g.nodes.filter((n) => n.kind === "hub").length;
      card.replaceChildren(el("h2", { text: `Network & assets (${hosts} managed, ${assets} discovered, ${hubs} subnets/groups)` }),
        el("div", { class: "trend-legend" },
          el("span", {}, el("span", { class: "trend-swatch", style: "background:#6b7278" }), "host, low risk"),
          el("span", {}, el("span", { class: "trend-swatch", style: "background:#d9a70f" }), "medium"),
          el("span", {}, el("span", { class: "trend-swatch", style: "background:#c0392b" }), "high / critical"),
          el("span", {}, el("span", { class: "trend-swatch", style: "background:#fff;border:2px dashed #9aa3a8" }), "discovered, unmanaged"),
          el("span", {}, el("span", { class: "trend-swatch", style: "background:#fff;border:2px solid #2f6fb3" }), "discovered, matches a host")),
        svg,
        el("p", { class: "meta", text: "Hosts sit on the /24 of their reported interface address (or their board group when the agent reports no interfaces); discovered assets sit on the subnet they were swept from. Click a host to open it." }));
    } catch (err) {
      card.replaceChildren(el("h2", { text: "Network & assets" }), el("p", { text: `Couldn't load graph: ${err.message}` }));
    }
    return card;
  }

  // bookmarksCard is "since last demo": snapshot now, then diff any
  // saved snapshot against the live fleet.
  async function bookmarksCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Since last time" }), el("p", { class: "meta", text: "Loading…" }));
    async function render() {
      try {
        const list = await api("/api/bookmarks");
        const nameInput = el("input", { type: "text", placeholder: "bookmark name, e.g. before the Island demo" });
        const saveBtn = el("button", { type: "button", text: "Bookmark now" });
        const msg = el("span", { class: "save-msg" });
        saveBtn.addEventListener("click", async () => {
          msg.textContent = "Saving…";
          try { await api("/api/bookmarks", { method: "POST", body: { name: nameInput.value.trim() } }); msg.textContent = ""; render(); }
          catch (err) { msg.textContent = `Error: ${err.message}`; }
        });
        const diffOut = el("div", {});
        const rows = list.map((b) => {
          const diffBtn = el("button", { type: "button", text: "What changed?" });
          diffBtn.addEventListener("click", async () => {
            diffOut.replaceChildren(el("p", { class: "meta", text: "Comparing…" }));
            try {
              const d = await api(`/api/bookmarks/${encodeURIComponent(b.id)}/diff`);
              const items = d.changes.map((c) => el("li", { class: "change-row" },
                el("span", { class: `change-action ${c.better ? "add" : c.worse ? "remove" : "update"}`, text: c.better ? "better" : c.worse ? "worse" : "changed" }),
                el("span", { class: "change-detail" }, c.host ? el("a", { href: `#/host/${encodeURIComponent(c.host)}`, text: c.host }) : null, `${c.host ? ": " : ""}${c.detail}`)));
              diffOut.replaceChildren(el("p", { text: d.summary }), items.length ? el("ul", { class: "changes-list" }, ...items) : el("p", { class: "meta", text: `Nothing changed (${d.unchanged_hosts} hosts identical).` }));
            } catch (err) { diffOut.replaceChildren(el("p", { text: `Error: ${err.message}` })); }
          });
          const delBtn = el("button", { type: "button", class: "ghost", text: "Delete" });
          delBtn.addEventListener("click", async () => {
            if (!confirm(`Delete bookmark "${b.name}"?`)) return;
            try { await api(`/api/bookmarks/${encodeURIComponent(b.id)}`, { method: "DELETE" }); render(); } catch (err) { msg.textContent = `Error: ${err.message}`; }
          });
          return el("li", { class: "policy-row" }, el("span", { class: "policy-name", text: b.name }),
            el("span", { class: "policy-condition", text: `${b.hosts} hosts, posture ${b.avg_posture}, risk ${b.avg_risk}` }),
            el("span", { class: "change-time", text: `${timeAgo(b.created_at)} by ${b.created_by}` }), diffBtn, delBtn);
        });
        card.replaceChildren(el("h2", { text: `Since last time (${list.length} bookmark${list.length === 1 ? "" : "s"})` }),
          el("p", { class: "meta", text: "Snapshot the fleet's headline state now; later, ask what changed since -- hosts added or gone, scores up or down, findings new or fixed. Built for opening a repeat demo with \"here's what's new.\"" }),
          el("div", { class: "editor-row" }, nameInput, saveBtn, msg),
          rows.length ? el("ul", { class: "policy-list" }, ...rows) : el("p", { text: "No bookmarks yet." }), diffOut);
      } catch (err) {
        card.replaceChildren(el("h2", { text: "Since last time" }), el("p", { text: `Couldn't load bookmarks: ${err.message}` }));
      }
    }
    await render();
    return card;
  }

  async function showFleet() {
    let summary;
    try {
      summary = await api("/api/summary");
    } catch (err) {
      app.replaceChildren(el("div", { class: "error-banner", text: `Couldn't load fleet summary: ${err.message}` }));
      return;
    }

    // Policies are readonly; the audit log is admin-only -- a
    // readonly/remediate key (or demo mode with no auth at all) simply
    // won't see the audit section rather than erroring the whole page.
    const [policiesResult, auditResult, discoveredResult] = await Promise.allSettled([api("/api/policies"), api("/api/audit?limit=20"), api("/api/discovered-assets")]);
    const policies = policiesResult.status === "fulfilled" ? policiesResult.value : [];
    const audit = auditResult.status === "fulfilled" ? auditResult.value : null;
    const discoveredAssets = discoveredResult.status === "fulfilled" ? discoveredResult.value : [];

    const heading = el(
      "div",
      { class: "section-heading" },
      el("h1", { text: "Fleet" }),
      el("span", { class: "meta", text: `${summary.total_hosts} host${summary.total_hosts === 1 ? "" : "s"}` })
    );

    const stats = el(
      "div",
      { class: "stat-grid" },
      statCard("Total hosts", summary.total_hosts),
      statCard("Stale hosts", summary.stale_hosts, summary.stale_hosts > 0 ? "stat-warn" : ""),
      el(
        "div",
        { class: "stat-card" },
        postureBadge(summary.average_posture_score),
        el("div", { class: "stat-label", text: "Average posture" })
      ),
      statCard("Hosts w/ vulnerabilities", summary.hosts_with_vulnerabilities, summary.hosts_with_vulnerabilities > 0 ? "stat-warn" : ""),
      statCard("Total findings", summary.total_vulnerability_findings, summary.total_vulnerability_findings > 0 ? "stat-warn" : ""),
      statCard("Shadow AI detections", summary.total_shadow_ai_findings, summary.total_shadow_ai_findings > 0 ? "stat-warn" : ""),
      statCard("Risky browser extensions", summary.total_risky_extensions || 0, summary.total_risky_extensions > 0 ? "stat-warn" : ""),
      statCard("OS past end of life", summary.hosts_os_eol || 0, summary.hosts_os_eol > 0 ? "stat-warn" : ""),
      statCard("Certificate issues", summary.hosts_with_cert_issues || 0, summary.hosts_with_cert_issues > 0 ? "stat-warn" : "")
    );

    const platformList = el("ul", { class: "platform-breakdown" });
    for (const [platform, count] of Object.entries(summary.by_platform || {}).sort()) {
      platformList.appendChild(
        el(
          "li",
          {},
          el("img", { class: "platform-icon", src: platformIcon(platform), alt: "" }),
          el("span", { text: platform }),
          el("span", { class: "count", text: String(count) })
        )
      );
    }
    const platformCard = el("div", { class: "fact-card" }, el("h2", { text: "By platform" }), platformList);

    const policiesFormSlot = el("div", {});
    const policiesListSlot = el("div", {});

    function renderPolicyList(list) {
      const listEl = list.length
        ? el("ul", { class: "policy-list" }, ...list.map((r) =>
            policyRow(r, async (target) => {
              if (!confirm(`Delete policy rule "${target.name}"?`)) return;
              try { await api(`/api/policies/${target.id}`, { method: "DELETE" }); refreshPolicies(); }
              catch (err) { alert(`Couldn't delete: ${err.message}`); }
            })
          ))
        : el("p", { text: "No policy rules configured yet." });
      policiesListSlot.replaceChildren(el("div", { class: "fact-card" }, el("h2", { text: `Policies (${list.length})` }), listEl));
    }
    async function refreshPolicies() {
      try {
        renderPolicyList(await api("/api/policies"));
      } catch (err) {
        policiesListSlot.replaceChildren(el("div", { class: "fact-card" }, el("p", { text: `Couldn't load policy rules: ${err.message} -- managing policies requires an admin API token.` })));
      }
    }
    policiesFormSlot.replaceChildren(el("div", { class: "fact-card" }, policyRuleForm(refreshPolicies)));
    renderPolicyList(policies);

    const discoveredSlot = el("div", {});
    function renderDiscovered(list) {
      const listEl = list.length
        ? el("ul", { class: "policy-list" }, ...list.map((a) =>
            discoveredAssetRow(a, async (target) => {
              if (!confirm(`Dismiss discovered asset "${target.address}"?`)) return;
              try { await api(`/api/discovered-assets/${target.id}`, { method: "DELETE" }); refreshDiscovered(); }
              catch (err) { alert(`Couldn't dismiss: ${err.message}`); }
            })
          ))
        : el("p", { text: "No unmanaged devices found yet -- run cmd/discover against a network range and it'll report in here." });
      discoveredSlot.replaceChildren(el("div", { class: "fact-card" }, el("h2", { text: `Discovered assets (${list.length})` }), listEl));
    }
    async function refreshDiscovered() {
      try {
        renderDiscovered(await api("/api/discovered-assets"));
      } catch (err) {
        discoveredSlot.replaceChildren(el("div", { class: "fact-card" }, el("p", { text: `Couldn't load discovered assets: ${err.message}` })));
      }
    }
    renderDiscovered(discoveredAssets);

    const trendSlot = el("div", {});
    trendCard(30).then((card) => trendSlot.replaceChildren(card));
    const riskSlot = el("div", {});
    riskCard().then((card) => riskSlot.replaceChildren(card));
    const benchSlot = el("div", {});
    benchmarkCard().then((card) => benchSlot.replaceChildren(card));
    const driftSlot = el("div", {});
    driftCard().then((card) => driftSlot.replaceChildren(card));
    const approvalsSlot = el("div", {});
    approvalsCard().then((card) => approvalsSlot.replaceChildren(card));
    const alertsSlot = el("div", {});
    alertsCard().then((card) => alertsSlot.replaceChildren(card));
    const signalsSlot = el("div", {});
    signalsCard().then((card) => signalsSlot.replaceChildren(card));
    const graphSlot = el("div", {});
    graphCard().then((card) => graphSlot.replaceChildren(card));
    const bookmarksSlot = el("div", {});
    bookmarksCard().then((card) => bookmarksSlot.replaceChildren(card));

    const nodes = [heading, stats, approvalsSlot, alertsSlot, signalsSlot, trendSlot, riskSlot, benchSlot, graphSlot, driftSlot, bookmarksSlot, reportsCard(), platformCard, policiesFormSlot, policiesListSlot, discoveredSlot];

    if (audit) {
      const auditList = audit.length
        ? el("ul", { class: "changes-list" }, ...audit.map(auditRow))
        : el("p", { text: "No audit entries recorded yet." });
      nodes.push(el("div", { class: "fact-card" }, el("h2", { text: "Recent activity" }), auditList));
    } else {
      nodes.push(
        el(
          "div",
          { class: "fact-card" },
          el("h2", { text: "Recent activity" }),
          el("p", { text: "Audit log requires an admin API key." })
        )
      );
    }

    app.replaceChildren(...nodes);
  }

  // PLATFORM_LABELS/PLATFORM_ORDER drive the enrollment form's <select>
  // -- five platforms, matching model.Enrollment.Platform's advisory
  // label set (see that struct's doc comment: it's never enforced
  // against what the host actually reports, just what the install/
  // download UI shows).
  const PLATFORM_LABELS = {
    linux: "Linux",
    windows: "Windows",
    macos: "macOS",
    android: "Android",
    ios: "iOS",
    chromeos: "ChromeOS",
  };
  const PLATFORM_ORDER = ["linux", "windows", "macos", "android", "ios", "chromeos"];

  // HOST_NAME_RE mirrors the agent scripts' assert_safe_token charset and
  // the server's own validHostName check (internal/api/server.go): the
  // TCP wire protocol header is space-delimited and the generated install
  // command drops the host name into a shell/PowerShell command line
  // unquoted, so anything outside letters/digits/'.'/'_'/'-' breaks
  // either one downstream. Checking it here means a bad host name is
  // caught before an enrollment (and its one-time token) is even created.
  const HOST_NAME_RE = /^[a-zA-Z0-9._-]{1,128}$/;

  // installSnippet builds the copy-paste command (or, for the two
  // mobile platforms, the setup details) an operator pastes into a
  // brand-new host right after minting its enrollment -- token is only
  // ever available here, once, in the moment right after creation (see
  // showAgents' create handler), never persisted or fetched again.
  function installSnippet(enrollment, token) {
    const apiHost = location.hostname || "<muster-host>";
    const dlBase = `${location.protocol}//${location.host}/api/agents/download`;
    switch (enrollment.platform) {
      case "linux":
      case "macos":
        return [
          `curl -fsSL ${dlBase}/${enrollment.platform} -o muster-agent.sh && chmod +x muster-agent.sh`,
          `./muster-agent.sh --muster-host ${apiHost} --muster-port 9090 --host-name ${enrollment.host} --token ${token}`,
        ].join("\n");
      case "windows":
        return [
          `Invoke-WebRequest ${dlBase}/windows -OutFile muster-agent.ps1`,
          `.\\muster-agent.ps1 -MusterHost ${apiHost} -MusterPort 9090 -HostName ${enrollment.host} -Token ${token}`,
        ].join("\n");
      default: // android / ios / chromeos -- no TCP one-liner, these use POST /api/mobile-report instead
        return [
          `Server URL:  ${location.protocol}//${location.host}/api/mobile-report`,
          `Host name:   ${enrollment.host}`,
          `Token:       ${token}`,
          "",
          enrollment.platform === "android"
            ? "Enter these three values in the Muster Android app's setup screen (agent/android/ -- build it in Android Studio first)."
            : enrollment.platform === "chromeos"
            ? "Push these three values as chrome.storage.managed policy (serverUrl/hostName/token) for the Muster extension via the Google Admin console -- see agent/chromeos/README.md."
            : "Enter these three values while building the Shortcuts automation in agent/ios/README.md.",
        ].join("\n");
    }
  }

  function enrollmentStatusBadge(status) {
    return el("span", { class: `posture-badge ${status === "enrolled" ? "posture-good" : "posture-warn"}`, text: status });
  }

  function enrollmentRow(enr, onRevoke) {
    const revokeBtn = el("button", { type: "button", class: "ghost", text: "Revoke" });
    revokeBtn.addEventListener("click", () => onRevoke(enr));
    const timing = enr.status === "enrolled"
      ? `enrolled ${timeAgo(enr.enrolled_at)}`
      : `created ${timeAgo(enr.created_at)}`;
    return el(
      "li",
      { class: "policy-row" },
      el("span", { class: "policy-name", text: enr.host }),
      el("span", { class: "policy-scope", text: PLATFORM_LABELS[enr.platform] || enr.platform }),
      enrollmentStatusBadge(enr.status),
      el("span", { class: "change-time", text: timing }),
      revokeBtn
    );
  }

  // copyToClipboard tries the modern Clipboard API first, then falls back
  // to the old execCommand("copy") trick via a hidden textarea.
  // navigator.clipboard is only defined in secure contexts (https, or
  // localhost) -- Muster is routinely reached over plain
  // http://<lan-ip>:8080 (see the dashboard's own address bar), where
  // navigator.clipboard is undefined, not merely rejecting, so the old
  // try/await/catch here never even reached the catch block; it threw
  // synchronously on `.writeText` and looked like the button did nothing.
  async function copyToClipboard(text) {
    if (window.isSecureContext && navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        // fall through to the execCommand fallback below
      }
    }
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    document.body.removeChild(textarea);
    return ok;
  }

  function revealPanel(enr, token) {
    const pre = el("pre", { class: "install-snippet", text: installSnippet(enr, token) });
    const copyBtn = el("button", { type: "button", text: "Copy" });
    copyBtn.addEventListener("click", async () => {
      const ok = await copyToClipboard(pre.textContent);
      if (ok) {
        copyBtn.textContent = "Copied";
        setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
      } else {
        // both copy paths failed -- select the text so the person can
        // still grab it with a manual Ctrl+C/Cmd+C
        const range = document.createRange();
        range.selectNodeContents(pre);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        copyBtn.textContent = "Selected -- press Ctrl+C";
        setTimeout(() => { copyBtn.textContent = "Copy"; }, 2500);
      }
    });
    return el(
      "div",
      { class: "reveal-panel" },
      el("p", {}, el("strong", { text: "Enrollment token for " + enr.host + " -- shown once, copy it now:" })),
      pre,
      copyBtn
    );
  }

  function enrollmentForm(onCreated) {
    const hostInput = el("input", { type: "text", placeholder: "host name, e.g. webbox04", autocomplete: "off" });
    const platformSelect = el("select", {}, ...PLATFORM_ORDER.map((p) => el("option", { value: p, text: PLATFORM_LABELS[p] })));
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "New enrollment" }),
      hostInput,
      platformSelect,
      el("button", { type: "submit", text: "Create" }),
      msg
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const host = hostInput.value.trim();
      if (!host) return;
      if (!HOST_NAME_RE.test(host)) {
        msg.textContent = "Host name may only contain letters, digits, '.', '_', '-' (no spaces) -- 1-128 characters.";
        return;
      }
      msg.textContent = "Creating...";
      try {
        const created = await api("/api/enrollments", { method: "POST", body: { host, platform: platformSelect.value } });
        msg.textContent = "";
        hostInput.value = "";
        onCreated(created, created.token);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return form;
  }

  function downloadsCard() {
    const list = el("ul", { class: "downloads-list" });
    for (const p of ["linux", "windows", "macos"]) {
      list.appendChild(
        el(
          "li",
          {},
          el("a", { href: `/api/agents/download/${p}`, download: "", text: `${PLATFORM_LABELS[p]} agent script` }),
          el("span", { class: "change-time", text: p === "windows" ? "muster-agent.ps1" : "muster-agent.sh" })
        )
      );
    }
    list.appendChild(el("li", {}, el("span", { text: "Android agent" }), el("span", { class: "change-time", text: "source in agent/android/ -- build with Android Studio" })));
    list.appendChild(el("li", {}, el("span", { text: "iOS" }), el("span", { class: "change-time", text: "no downloadable app -- see agent/ios/README.md for the Shortcuts-based setup" })));
    list.appendChild(el("li", {}, el("span", { text: "ChromeOS extension" }), el("span", { class: "change-time", text: "source in agent/chromeos/ -- load unpacked or force-install via Google Admin console" })));
    return el("div", { class: "fact-card" }, el("h2", { text: "Download agents" }), list);
  }

  // airgapImportCard is the paste-in counterpart to a host running
  // muster-agent.sh/.ps1 with --airgap-out on a machine with no route to
  // Muster at all: carry the JSON blob it produces here by hand (USB
  // drive, retyped, a QR scan -- see agent/airgap/README.md) and submit
  // it from wherever the dashboard itself is reachable. No file upload,
  // just a text box -- that's the whole point of a format small/plain
  // enough to move by sneakernet.
  function airgapImportCard() {
    const textarea = el("textarea", { rows: "6", placeholder: '{"platform":"linux","host":"...","payload_b64":"..."}', class: "airgap-textarea" });
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row airgap-form" },
      el("label", { text: "Air-gapped import" }),
      textarea,
      el("button", { type: "submit", text: "Submit report" }),
      msg
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      let parsed;
      try {
        parsed = JSON.parse(textarea.value.trim());
      } catch (err) {
        msg.textContent = "That doesn't look like valid JSON -- paste the whole blob the script printed/wrote, unedited.";
        return;
      }
      if (!parsed.platform || !parsed.host || !parsed.payload_b64) {
        msg.textContent = 'Missing platform/host/payload_b64 -- paste the whole blob, not a fragment of it.';
        return;
      }
      msg.textContent = "Submitting...";
      try {
        const result = await api("/api/airgap-report", { method: "POST", body: parsed });
        msg.textContent = `Recorded -- ${result.changes} field(s) changed for ${result.host}.`;
        textarea.value = "";
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return el(
      "div", { class: "fact-card" },
      el("h2", { text: "Air-gapped import" }),
      el("p", { class: "meta", text: "Paste the JSON blob produced by running an agent script with --airgap-out on a host that has no network route to Muster." }),
      form
    );
  }

  // agentHealthCard is the Agents tab's collector-health view (see
  // internal/agenthealth): per host, when the agent last checked in,
  // its usual cadence, whether it's late/missing/failing, and how many
  // report attempts failed -- the agents themselves, not the data.
  async function agentHealthCard() {
    const card = el("div", { class: "fact-card" }, el("h2", { text: "Agent health" }), el("p", { class: "meta", text: "Loading…" }));
    try {
      const d = await api("/api/agents/health");
      const c = d.counts || {};
      const stats = el("div", { class: "stat-grid" },
        statCard("Healthy", c.healthy || 0),
        statCard("Late", c.late || 0, c.late ? "stat-warn" : ""),
        statCard("Missing", c.missing || 0, c.missing ? "stat-warn" : ""),
        statCard("Failing", c.failing || 0, c.failing ? "stat-warn" : ""),
        statCard("Never reported", c.never || 0));
      const pill = (st) => el("span", { class: `severity-pill ${st === "failing" || st === "missing" ? "severity-critical" : st === "late" ? "severity-medium" : "severity-low"}`, text: st });
      const rows = d.agents.map((a) => el("li", { class: "policy-row" },
        pill(a.state),
        el("a", { href: `#/host/${encodeURIComponent(a.host)}`, class: "policy-name", text: a.host }),
        el("span", { class: "policy-condition", text: a.detail }),
        el("span", { class: "change-time", text: `${a.checkins || 0} check-in${a.checkins === 1 ? "" : "s"}${a.path ? ` via ${a.path}` : ""}${a.failures ? `, ${a.failures} failure${a.failures === 1 ? "" : "s"}` : ""}` })));
      card.replaceChildren(el("h2", { text: `Agent health (${d.agents.length})` }),
        el("p", { class: "meta", text: "\"Stale\" says a host hasn't reported in 24 hours; this says the agent that usually reports every 30 minutes is 3 hours late, or that something is presenting a wrong token for a host name. Recorded on every report attempt over TCP, mobile, cloud and air-gap paths." }),
        stats, rows.length ? el("ul", { class: "policy-list" }, ...rows) : el("p", { text: "No agents have reported yet." }));
    } catch (err) {
      card.replaceChildren(el("h2", { text: "Agent health" }), el("p", { text: `Couldn't load: ${err.message}` }));
    }
    return card;
  }

  async function showAgents() {
    const heading = el(
      "div",
      { class: "section-heading" },
      el("h1", { text: "Agents" }),
      el("span", { class: "meta", text: "Enroll a new host, or download an agent to install by hand" })
    );

    const revealSlot = el("div", {});
    const listSlot = el("div", {});

    async function refreshList() {
      try {
        const enrollments = await api("/api/enrollments");
        const list = enrollments.length
          ? el("ul", { class: "policy-list" }, ...enrollments.map((enr) =>
              enrollmentRow(enr, async (target) => {
                if (!confirm(`Revoke the enrollment for ${target.host}?`)) return;
                try {
                  await api(`/api/enrollments/${target.id}`, { method: "DELETE" });
                  refreshList();
                } catch (err) {
                  alert(`Couldn't revoke: ${err.message}`);
                }
              })
            ))
          : el("p", { text: "No enrollments yet -- create one above." });
        listSlot.replaceChildren(el("div", { class: "fact-card" }, el("h2", { text: `Enrollments (${enrollments.length})` }), list));
      } catch (err) {
        listSlot.replaceChildren(
          el(
            "div",
            { class: "fact-card" },
            el("h2", { text: "Enrollments" }),
            el("p", { text: `Couldn't load enrollments: ${err.message} -- creating and listing enrollments requires an admin API token (set one above).` })
          )
        );
      }
    }

    const form = enrollmentForm((created, token) => {
      revealSlot.replaceChildren(revealPanel(created, token));
      refreshList();
    });

    const healthSlot = el("div", {});
    agentHealthCard().then((card) => healthSlot.replaceChildren(card));
    app.replaceChildren(heading, form, revealSlot, listSlot, healthSlot, downloadsCard(), airgapImportCard());
    await refreshList();
  }


  // renderMarkdown is a small, hand-written subset renderer -- headers,
  // paragraphs, fenced code blocks, inline code/bold, unordered lists,
  // and pipe tables. Not a CommonMark implementation; just enough for
  // this project's own docs/*.md, which are written plainly on purpose.
  // No CDN dependency, matching the rest of this dashboard's
  // dependency-free-vanilla-JS philosophy.
  function renderMarkdown(md) {
    const lines = md.replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let i = 0;
    let listBuf = null;
    let tableBuf = null;

    function flushList() {
      if (listBuf) { out.push(listBuf); listBuf = null; }
    }
    function flushTable() {
      if (tableBuf) { out.push(tableBuf); tableBuf = null; }
    }
    function inline(text) {
      // Order matters: code spans first so ** inside `code` isn't touched.
      const frag = document.createDocumentFragment();
      const codeRe = /`([^`]+)`/g;
      let lastIndex = 0;
      let m;
      const parts = [];
      while ((m = codeRe.exec(text)) !== null) {
        parts.push({ text: text.slice(lastIndex, m.index), code: false });
        parts.push({ text: m[1], code: true });
        lastIndex = codeRe.lastIndex;
      }
      parts.push({ text: text.slice(lastIndex), code: false });
      for (const part of parts) {
        if (part.code) {
          frag.appendChild(el("code", { text: part.text }));
          continue;
        }
        // bold **text**
        const boldRe = /\*\*([^*]+)\*\*/g;
        let li = 0, bm;
        while ((bm = boldRe.exec(part.text)) !== null) {
          if (bm.index > li) frag.appendChild(document.createTextNode(part.text.slice(li, bm.index)));
          frag.appendChild(el("strong", { text: bm[1] }));
          li = boldRe.lastIndex;
        }
        if (li < part.text.length) frag.appendChild(document.createTextNode(part.text.slice(li)));
      }
      return frag;
    }

    while (i < lines.length) {
      const line = lines[i];

      if (line.startsWith("```")) {
        flushList(); flushTable();
        const code = [];
        i++;
        while (i < lines.length && !lines[i].startsWith("```")) { code.push(lines[i]); i++; }
        out.push(el("pre", { class: "install-snippet" }, el("code", { text: code.join("\n") })));
        i++;
        continue;
      }

      const headerMatch = line.match(/^(#{1,3})\s+(.*)$/);
      if (headerMatch) {
        flushList(); flushTable();
        const tag = "h" + Math.min(headerMatch[1].length + 1, 4); // # -> h2 (h1 is the page title), ## -> h3, ### -> h4
        const h = el(tag, {});
        h.appendChild(inline(headerMatch[2]));
        out.push(h);
        i++;
        continue;
      }

      if (/^\s*-\s+/.test(line)) {
        flushTable();
        if (!listBuf) listBuf = el("ul", { class: "docs-list" });
        const li = el("li", {});
        li.appendChild(inline(line.replace(/^\s*-\s+/, "")));
        listBuf.appendChild(li);
        i++;
        continue;
      }
      flushList();

      if (/^\s*\|.*\|\s*$/.test(line)) {
        const next = lines[i + 1] || "";
        if (!tableBuf && /^\s*\|[\s:|-]+\|\s*$/.test(next)) {
          // header row + separator row -- start a table, skip the separator
          const headCells = line.split("|").slice(1, -1).map((c) => c.trim());
          tableBuf = el("table", { class: "docs-table" },
            el("thead", {}, el("tr", {}, ...headCells.map((c) => el("th", { text: c }))))
          );
          tableBuf.appendChild(el("tbody", {}));
          i += 2;
          continue;
        }
        if (tableBuf) {
          const cells = line.split("|").slice(1, -1).map((c) => c.trim());
          const tbody = tableBuf.querySelector("tbody");
          const row = el("tr", {});
          for (const c of cells) {
            const td = el("td", {});
            td.appendChild(inline(c));
            row.appendChild(td);
          }
          tbody.appendChild(row);
          i++;
          continue;
        }
      }
      flushTable();

      if (line.trim() === "") { i++; continue; }

      const p = el("p", {});
      p.appendChild(inline(line));
      out.push(p);
      i++;
    }
    flushList();
    flushTable();
    return out;
  }

  async function showDocs() {
    const heading = el("div", { class: "section-heading" }, el("h1", { text: "Docs" }));
    const nav = el("ul", { class: "docs-nav" });
    const body = el("div", { class: "docs-body" }, el("p", { text: "Loading..." }));
    app.replaceChildren(heading, el("div", { class: "docs-layout" }, nav, body));

    let pages = [];
    try {
      pages = await api("/api/docs");
    } catch (err) {
      body.replaceChildren(el("p", { text: `Couldn't load the docs index: ${err.message}` }));
      return;
    }

    async function loadPage(name) {
      for (const a of nav.querySelectorAll("a")) a.classList.toggle("active", a.dataset.doc === name);
      body.replaceChildren(el("p", { text: "Loading..." }));
      try {
        const res = await fetch(`/api/docs/${encodeURIComponent(name)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const md = await res.text();
        body.replaceChildren(...renderMarkdown(md));
      } catch (err) {
        body.replaceChildren(el("p", { text: `Couldn't load this page: ${err.message}` }));
      }
    }

    for (const p of pages) {
      const a = el("a", { href: "#", "data-doc": p.name, text: p.title });
      a.addEventListener("click", (e) => { e.preventDefault(); loadPage(p.name); });
      nav.appendChild(el("li", {}, a));
    }
    if (pages.length) loadPage(pages[0].name);
  }

  function boolLabel(b) {
    return b ? "Yes" : "No";
  }

  // settingsTable renders one GET /api/settings section as a fact-card,
  // the same table/titleCase-free "hand-written label" shape
  // showHostDetail's generic fact categories use (fact-table inside a
  // fact-card), except here the row labels are written out rather than
  // derived from a JSON key, since this is a small fixed set of fields
  // a human reads directly, not an arbitrary fact category.
  function settingsTable(title, rows) {
    const table = el("table", { class: "fact-table" });
    for (const [label, value] of rows) {
      if (value == null) continue;
      const tr = el("tr");
      tr.appendChild(el("td", { text: label }));
      tr.appendChild(el("td", { text: String(value) }));
      table.appendChild(tr);
    }
    return el("div", { class: "fact-card" }, el("h2", { text: title }), table);
  }

  // settingsCardWithForm renders a settingsTable's rows plus an editor
  // form beneath them, in one fact-card -- same shape settingsTable
  // itself produces, just with a form appended, so the SIEM Forwarding
  // and Ask Muster sections read the same as the other four (General,
  // Authentication, Vulnerability feed, Webhooks) but are actually
  // editable.
  function settingsCardWithForm(title, rows, form) {
    const table = el("table", { class: "fact-table" });
    for (const [label, value] of rows) {
      if (value == null) continue;
      const tr = el("tr");
      tr.appendChild(el("td", { text: label }));
      tr.appendChild(el("td", { text: String(value) }));
      table.appendChild(tr);
    }
    return el("div", { class: "fact-card" }, el("h2", { text: title }), table, form);
  }

  // notificationsTester is the Settings page's "send a test event"
  // control for the notification sinks (POST /api/notifications/test),
  // reporting each sink's outcome inline.
  function notificationsTester(s) {
    const msg = el("span", { class: "save-msg" });
    const results = el("ul", { class: "posture-findings" });
    const btn = el("button", { type: "button", text: "Send test event" });
    btn.addEventListener("click", async () => {
      msg.textContent = "Sending…";
      results.replaceChildren();
      try {
        const r = await api("/api/notifications/test", { method: "POST", body: {} });
        msg.textContent = "";
        for (const [sink, outcome] of Object.entries(r.results)) results.appendChild(el("li", { text: `${sink}: ${outcome}` }));
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    const wrap = el("div", {});
    wrap.append(el("div", { class: "editor-row" }, el("label", { text: s.webhooks.configured ? "Sinks are set with -webhook-url, -slack-webhook-url, -teams-webhook-url, -jira-*, -servicenow-* (flags/env)" : "No sinks configured -- set -webhook-url, -slack-webhook-url, -teams-webhook-url, -jira-* or -servicenow-* (flags/env) and restart" }), btn, msg), results);
    return wrap;
  }

  // siemForwardingEditor is the SIEM Forwarding card's edit form --
  // PATCH /api/settings, live (no restart) via internal/siemforward.Dynamic,
  // persisted via internal/settingsstore when the server was started
  // with a data dir. GET /api/settings never returns the HEC URL or
  // token (see settingsSIEM), so unlike groupEditor/tagEditor this
  // can't prefill from the current value -- changing anything means
  // retyping both fields, same "all-or-nothing pair" the -siem-hec-*
  // flags themselves enforce.
  function siemForwardingEditor(s) {
    const backends = (s.siem && s.siem.backends) || ["splunk-hec"];
    const backendSelect = el("select", {}, ...backends.map((b) => el("option", { value: b, text: b, selected: b === (s.siem.backend || "splunk-hec") ? "selected" : null })));
    for (const o of backendSelect.options) if (o.getAttribute("selected") === "null") o.removeAttribute("selected");
    const urlInput = el("input", { type: "text", placeholder: "https://splunk.example.com:8088 (or Sumo source / LogRhythm webhook URL)" });
    const tokenInput = el("input", { type: "password", placeholder: "token (required for Splunk HEC)" });
    const disableBox = el("input", { type: "checkbox" });
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "Backend" }), backendSelect,
      el("label", { text: "URL" }), urlInput,
      el("label", { text: "Token" }), tokenInput,
      el("label", { text: "Disable" }), disableBox,
      el("button", { type: "submit", text: "Save" }),
      msg
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const body = {};
      if (disableBox.checked) {
        if (!s.siem.configured) { msg.textContent = "Nothing to save"; return; }
        body.siem_disable = true;
      } else {
        const url = urlInput.value.trim();
        const token = tokenInput.value.trim();
        if (!url && !token) { msg.textContent = "Nothing to save"; return; }
        if (!url || (!token && backendSelect.value === "splunk-hec")) { msg.textContent = "Error: Splunk HEC needs both URL and token; the other backends need the URL"; return; }
        body.siem_backend = backendSelect.value;
        body.siem_hec_url = url;
        body.siem_hec_token = token;
      }
      msg.textContent = "Saving…";
      try {
        await api("/api/settings", { method: "PATCH", body });
        msg.textContent = "Saved";
        setTimeout(showSettings, 800);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return form;
  }

  // askMusterEditor is the Ask Muster card's edit form -- PATCH
  // /api/settings, live (no restart) via internal/aiquery.ConfigStore,
  // persisted via internal/settingsstore when the server was started
  // with a data dir. Unlike the SIEM form, the model field is
  // pre-filled from the current snapshot (the model name isn't a
  // secret) so changing just the model doesn't require retyping the
  // API key -- the server keeps the existing key when ai_api_key is
  // omitted from the request.
  function askMusterEditor(s) {
    const backends = s.ask_muster.backends || ["anthropic", "openai-compatible"];
    const current = s.ask_muster.backend || "anthropic";
    const backendSelect = el("select", {}, ...backends.map((b) => el("option", { value: b, text: b })));
    backendSelect.value = current;
    const modelInput = el("input", { type: "text", value: s.ask_muster.model || "" });
    const baseInput = el("input", { type: "text", class: "wide", placeholder: "https://router.huggingface.co/v1", value: "" });
    const keyInput = el("input", { type: "password" });
    const disableBox = el("input", { type: "checkbox" });
    const msg = el("span", { class: "save-msg" });
    const baseLabel = el("label", { text: "Base URL" });
    const hint = el("p", { class: "meta" });

    // The two backends need genuinely different things, so the form
    // says which: Anthropic takes a key and has a default model, while
    // an OpenAI-compatible server takes a URL, needs an explicit model
    // name, and often needs no credential at all.
    function syncBackend() {
      const openai = backendSelect.value === "openai-compatible";
      baseLabel.hidden = !openai;
      baseInput.hidden = !openai;
      modelInput.placeholder = openai ? "e.g. qwen3:30b-a3b or a Hugging Face model id" : "claude-opus-5 (default)";
      keyInput.placeholder = s.ask_muster.configured && current === backendSelect.value
        ? "leave blank to keep current key"
        : (openai ? "optional: HF token, or blank for a local server" : "sk-ant-...");
      hint.textContent = openai
        ? "Any server speaking OpenAI chat-completions: Hugging Face's router, or LM Studio, Ollama, vLLM or TGI on your own hardware. A model you host keeps fleet data on your network, which is the point for this kind of tool."
        : "Anthropic's Messages API. Fleet context leaves your network with every question.";
    }
    backendSelect.addEventListener("change", syncBackend);
    syncBackend();

    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "Backend" }), backendSelect,
      el("label", { text: "Model" }), modelInput,
      baseLabel, baseInput,
      el("label", { text: "API key" }), keyInput,
      el("label", { text: "Disable" }), disableBox,
      el("button", { type: "submit", text: "Save" }),
      msg
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const body = {};
      if (disableBox.checked) {
        if (!s.ask_muster.configured) { msg.textContent = "Nothing to save"; return; }
        body.ai_disable = true;
      } else {
        const key = keyInput.value.trim();
        const model = modelInput.value.trim();
        const backend = backendSelect.value;
        const baseURL = baseInput.value.trim();
        const switching = backend !== current;
        if (backend === "openai-compatible") {
          if (!baseURL && (switching || !s.ask_muster.base_url)) {
            msg.textContent = "Error: a base URL is required, e.g. http://your-host:11434/v1";
            return;
          }
          if (!model) { msg.textContent = "Error: a model name is required for this backend"; return; }
        } else if (!key && (switching || !s.ask_muster.configured)) {
          msg.textContent = "Error: an API key is required to enable Ask Muster";
          return;
        }
        if (key) body.ai_api_key = key;
        body.ai_model = model;
        body.ai_backend = backend;
        if (baseURL) body.ai_base_url = baseURL;
      }
      msg.textContent = "Saving…";
      try {
        await api("/api/settings", { method: "PATCH", body });
        msg.textContent = "Saved";
        setTimeout(showSettings, 800);
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return el("div", {}, form, hint);
  }


  // showSettings is GET /api/settings, rendered read-only -- admin-gated
  // server-side (internal/api's handleSettings), not hidden client-side:
  // same "always show the tab, let a failed call explain why" pattern
  // as Fleet's audit-log section and the Policies/Enrollments tabs, so
  // a readonly/remediate credential (or demo mode with no auth at all)
  // sees a clear "needs admin" message here instead of the tab just not
  // existing.
  async function showSettings() {
    const heading = el("div", { class: "section-heading" }, el("h1", { text: "Settings" }));

    let s;
    try {
      s = await api("/api/settings");
    } catch (err) {
      app.replaceChildren(
        heading,
        el("div", { class: "fact-card" }, el("p", { text: `Couldn't load settings: ${err.message} -- viewing server settings requires an admin API token (set one above) or an admin OAuth session.` }))
      );
      return;
    }

    const general = settingsTable("General", [
      ["Storage backend", s.storage_backend],
      ["Ingest address", s.ingest_addr],
      ["API address", s.api_addr],
      ["Evaluator interval", s.evaluator_interval],
    ]);

    const auth = settingsTable("Authentication", [
      ["Bearer token configured", boolLabel(s.auth.bearer_token_configured)],
      ["OAuth configured", boolLabel(s.auth.oauth_configured)],
      ["OAuth role map", (s.auth.oauth_role_map || []).join(", ") || null],
    ]);

    const vulnFeed = settingsTable("Vulnerability feed", [
      ["Enabled", boolLabel(s.vuln_feed.enabled)],
      ["Interval", s.vuln_feed.interval || null],
    ]);

    const askMuster = settingsCardWithForm("Ask Muster", [
      ["Configured", boolLabel(s.ask_muster.configured)],
      ["Backend", s.ask_muster.backend || null],
      ["Model", s.ask_muster.model || null],
      ["Base URL", s.ask_muster.base_url || null],
    ], askMusterEditor(s));

    const webhooks = settingsCardWithForm("Notifications", [
      ["Configured", boolLabel(s.webhooks.configured)],
      ["Sinks", (s.webhooks.sinks || []).join(", ") || null],
      ["Queued deliveries", s.webhooks.pending],
      ["Dead letters", s.webhooks.dead],
    ], notificationsTester(s));

    const siem = settingsCardWithForm("SIEM forwarding", [
      ["Configured", boolLabel(s.siem.configured)],
      ["Backend", s.siem.backend || null],
    ], siemForwardingEditor(s));

    app.replaceChildren(heading, general, auth, vulnFeed, askMuster, webhooks, siem, demoCard());
  }

  // demoCard is the Settings page's simulator: fire synthetic events
  // through the real audit/notification/SIEM paths on demand.
  function demoCard() {
    const msg = el("span", { class: "save-msg" });
    const out = el("ul", { class: "posture-findings" });
    const hostInput = el("input", { type: "text", placeholder: "host (optional)" });
    const row = el("div", { class: "editor-row" }, el("label", { text: "Host" }), hostInput, msg);
    const buttons = el("div", { class: "editor-row" });
    api("/api/demo/scenarios").then((scenarios) => {
      for (const [name, desc] of Object.entries(scenarios)) {
        const b = el("button", { type: "button", text: name.replace(/_/g, " "), title: desc });
        b.addEventListener("click", async () => {
          msg.textContent = "Firing…";
          try {
            const r = await api("/api/demo/simulate", { method: "POST", body: { scenario: name, host: hostInput.value.trim() } });
            msg.textContent = "";
            out.replaceChildren(el("li", { text: `${r.scenario} on ${r.host}: fired ${r.fired.join(", ")} -- ${r.sinks} notification sink(s) in play. ${r.note}` }));
          } catch (err) { msg.textContent = `Error: ${err.message}`; }
        });
        buttons.appendChild(b);
      }
    }).catch(() => buttons.appendChild(el("span", { class: "meta", text: "Scenarios unavailable." })));
    return el("div", { class: "fact-card" }, el("h2", { text: "Demo / simulator" }),
      el("p", { class: "meta", text: "Fire a synthetic finding through the same paths a real one takes -- audit trail (and SIEM forwarding), the notification queue, the behavioral signals -- so the \"it happened, it forwarded\" moment can be shown on demand. Entries are marked (simulated). Admin only." }),
      row, buttons, out);
  }

  function complianceScoreBadge(score) {
    const cls = score >= 90 ? "posture-good" : score >= 60 ? "posture-warn" : "posture-bad";
    return el("span", { class: `posture-badge ${cls}`, text: `${score}%` });
  }

  function softwareRuleRow(rule, onDelete) {
    const delBtn = el("button", { type: "button", class: "ghost", text: "Delete" });
    delBtn.addEventListener("click", () => onDelete(rule));
    return el(
      "li",
      { class: "policy-row" },
      el("span", { class: "policy-name", text: rule.name }),
      el("span", { class: "policy-scope", text: rule.kind === "deny" ? "Deny" : "Allow" }),
      el("span", { class: "policy-condition", text: rule.match }),
      el("span", { class: "change-time", text: rule.group ? `group: ${rule.group}` : "all hosts" }),
      delBtn
    );
  }

  function softwareRuleForm(onCreated) {
    const nameInput = el("input", { type: "text", placeholder: "rule name" });
    const kindSelect = el("select", {}, el("option", { value: "deny", text: "Deny" }), el("option", { value: "allow", text: "Allow" }));
    const matchInput = el("input", { type: "text", placeholder: "package name, or prefix*" });
    const groupInput = el("input", { type: "text", placeholder: "group (optional)" });
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "New software rule" }),
      nameInput, kindSelect, matchInput, groupInput,
      el("button", { type: "submit", text: "Create" }),
      msg
    );
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = nameInput.value.trim();
      const match = matchInput.value.trim();
      if (!name || !match) return;
      msg.textContent = "Creating...";
      try {
        await api("/api/software-rules", { method: "POST", body: { name, kind: kindSelect.value, match, group: groupInput.value.trim() } });
        msg.textContent = "";
        nameInput.value = ""; matchInput.value = ""; groupInput.value = "";
        onCreated();
      } catch (err) {
        msg.textContent = `Error: ${err.message}`;
      }
    });
    return form;
  }

  // ENTITY_KIND_SHAPES maps an entity kind to the shape it draws as.
  // Shape carries the kind because color is already carrying the
  // family: a node-link diagram can put any two nodes side by side, and
  // past three categorical hues a palette stops separating every pair
  // for colorblind readers. Three family hues plus seven shapes gets
  // both dimensions across without failing that check.
  function entityShape(kind, r) {
    const pts = (list) => list.map(([x, y]) => `${x},${y}`).join(" ");
    const poly = (n, rot) => {
      const out = [];
      for (let i = 0; i < n; i++) {
        const a = rot + (2 * Math.PI * i) / n;
        out.push([(r * Math.cos(a)).toFixed(1), (r * Math.sin(a)).toFixed(1)]);
      }
      return out;
    };
    switch (kind) {
      case "group":
        return svgEl("rect", { x: -r, y: -r, width: 2 * r, height: 2 * r, rx: r * 0.42, class: "ent-node-shape" });
      case "rule":
        return svgEl("rect", { x: -r * 0.86, y: -r * 0.86, width: r * 1.72, height: r * 1.72, class: "ent-node-shape" });
      case "package":
        return svgEl("polygon", { points: pts(poly(6, 0)), class: "ent-node-shape" });
      case "cve":
        return svgEl("polygon", { points: pts(poly(4, -Math.PI / 2)), class: "ent-node-shape" });
      case "certificate":
        return svgEl("polygon", { points: pts(poly(3, -Math.PI / 2)), class: "ent-node-shape" });
      case "extension":
        return svgEl("polygon", { points: pts(poly(5, -Math.PI / 2)), class: "ent-node-shape" });
      default:
        return svgEl("circle", { r: r, class: "ent-node-shape" });
    }
  }

  const ENTITY_FAMILY_COLOR = { asset: "var(--ent-asset)", finding: "var(--ent-finding)", policy: "var(--ent-policy)" };
  const ENTITY_KIND_LABEL = {
    host: "host", group: "board group", package: "package", cve: "vulnerability",
    certificate: "certificate", extension: "browser extension", rule: "rule",
  };
  const ENTITY_EDGE_LABEL = {
    member: "is in", installs: "installs", "affected-by": "affected by",
    "exposed-to": "exposed to", presents: "presents", governs: "governs",
    indirect: "indirectly linked to",
  };

  // truncate keeps a direct label from running over its neighbors; the
  // full text is always in the tooltip and the table view.
  function truncate(s, max) {
    s = String(s || "");
    return s.length > max ? s.slice(0, max - 1) + "…" : s;
  }

  // showEntities is the Entity map tab: the fleet's entities and the
  // relationships between them, as one traversable picture instead of
  // a dozen separate lists.
  async function showEntities() {
    const state = {
      types: new Set(),          // empty = every kind
      focus: null,
      depth: 2,
      table: false,
      kinds: [],
    };

    const heading = el(
      "div", { class: "section-heading" },
      el("h1", { text: "Entity map" }),
      el("span", { class: "meta", text: "Hosts, groups, notable packages, vulnerabilities, certificates, extensions and rules, and how they connect" })
    );
    const slot = el("div", {});
    app.replaceChildren(heading, slot);

    try {
      const meta = await api("/api/entities/kinds");
      state.kinds = meta.kinds || [];
    } catch (err) {
      // The legend can fall back to whatever the graph itself returns.
      state.kinds = [];
    }

    async function render() {
      const card = el("div", { class: "fact-card" }, el("h2", { text: "Entity map" }), el("p", { class: "meta", text: "Loading…" }));
      slot.replaceChildren(card);
      let g;
      try {
        const params = new URLSearchParams();
        if (state.types.size) params.set("types", [...state.types].join(","));
        if (state.focus) { params.set("focus", state.focus); params.set("depth", String(state.depth)); }
        g = await api(`/api/entities${params.toString() ? "?" + params.toString() : ""}`);
      } catch (err) {
        card.replaceChildren(el("h2", { text: "Entity map" }), el("p", { text: `Couldn't load the entity map: ${err.message}` }));
        return;
      }

      const kinds = state.kinds.length ? state.kinds : [...new Set(g.nodes.map((n) => n.kind))].map((k) => ({ kind: k, family: "asset" }));
      const famOf = {};
      for (const k of kinds) famOf[k.kind] = k.family;

      // --- filter row: one row above the graph
      const chips = kinds.map((k) => {
        const on = state.types.size === 0 || state.types.has(k.kind);
        const count = (g.counts || {})[k.kind] || 0;
        const chip = el("button", { type: "button", class: "ent-chip", "aria-pressed": String(on), title: `${ENTITY_KIND_LABEL[k.kind] || k.kind} (${count} in the fleet)` },
          el("span", { class: "ent-chip-swatch", style: `background:${ENTITY_FAMILY_COLOR[k.family] || "#6b7278"}` }),
          el("span", { text: ENTITY_KIND_LABEL[k.kind] || k.kind }),
          el("span", { class: "ent-chip-count", text: String(count) }));
        chip.addEventListener("click", () => {
          // An empty set means "everything", so the first click has to
          // materialize the full set before removing one from it.
          if (state.types.size === 0) for (const kk of kinds) state.types.add(kk.kind);
          if (state.types.has(k.kind)) state.types.delete(k.kind); else state.types.add(k.kind);
          if (state.types.size === 0 || state.types.size === kinds.length) state.types.clear();
          render();
        });
        return chip;
      });
      const filters = el("div", { class: "ent-filters" }, el("span", { class: "ent-filter-label", text: "Show" }), ...chips);
      if (state.types.size) {
        const reset = el("button", { type: "button", class: "ghost", text: "All kinds" });
        reset.addEventListener("click", () => { state.types.clear(); render(); });
        filters.appendChild(reset);
      }
      if (state.focus) {
        const depth = el("select", { title: "How many hops from the focused entity" },
          ...[1, 2, 3, 4].map((d) => el("option", { value: String(d), text: `${d} hop${d > 1 ? "s" : ""}` })));
        depth.value = String(state.depth);
        depth.addEventListener("change", () => { state.depth = Number(depth.value); render(); });
        const clear = el("button", { type: "button", class: "ghost", text: "Whole fleet" });
        clear.addEventListener("click", () => { state.focus = null; render(); });
        filters.appendChild(el("span", { class: "ent-filter-label", text: "Within" }));
        filters.appendChild(depth);
        filters.appendChild(clear);
      }
      const tableToggle = el("button", { type: "button", class: "ghost", text: state.table ? "Hide table" : "Show table" });
      tableToggle.addEventListener("click", () => { state.table = !state.table; render(); });
      filters.appendChild(tableToggle);

      // --- the graph itself
      const svg = svgEl("svg", { viewBox: `0 0 ${g.width} ${g.height}`, class: "entity-graph", role: "img",
        "aria-label": `Entity relationship map: ${g.nodes.length} entities, ${g.edges.length} relationships` });
      const byID = {};
      for (const n of g.nodes) byID[n.id] = n;

      const edgesOf = {};   // node id -> edge elements touching it
      for (const e of g.edges) {
        const a = byID[e.from], b = byID[e.to];
        if (!a || !b) continue;
        const line = svgEl("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: `ent-edge ent-edge-${e.kind}` });
        line.appendChild(svgEl("title", { text: `${a.label} ${ENTITY_EDGE_LABEL[e.kind] || e.kind} ${b.label}` }));
        svg.appendChild(line);
        (edgesOf[e.from] = edgesOf[e.from] || []).push(line);
        (edgesOf[e.to] = edgesOf[e.to] || []).push(line);
      }

      // Direct labels are selective, and which ones fit was worked out
      // server-side against the real geometry (see
      // entitygraph.assignLabels) -- the focused node always gets one.
      // Every name is in the tooltip and the table view regardless.
      const wrap = el("div", { class: "entity-graph-wrap" });
      const tip = el("div", { class: "ent-tip", style: "display:none" });

      for (const n of g.nodes) {
        const cls = ["ent-node", `ent-fam-${n.family}`, `ent-kind-${n.kind}`];
        if (n.status) cls.push(`ent-status-${n.status}`);
        if (state.focus === n.id) cls.push("ent-node-focused");
        const grp = svgEl("g", { class: cls.join(" "), transform: `translate(${n.x},${n.y})`,
          tabindex: "0", role: "button", "aria-label": `${ENTITY_KIND_LABEL[n.kind] || n.kind} ${n.label}${n.status ? ", " + n.status : ""}` });
        grp.appendChild(entityShape(n.kind, n.r));
        if (n.status) grp.appendChild(svgEl("circle", { r: n.r + 3.5, class: "ent-status-ring" }));
        if (state.focus === n.id) grp.appendChild(svgEl("circle", { r: n.r + (n.status ? 8 : 5), class: "ent-focus-halo" }));
        if (n.show_label || state.focus === n.id) {
          // Where the label sits was decided server-side against the
          // real geometry, so it lands in whichever direction was free.
          const attrs = { class: "ent-label", text: truncate(n.label, 24) };
          switch (n.label_anchor) {
            case "above": attrs.y = -n.r - 6; attrs["text-anchor"] = "middle"; break;
            case "right": attrs.x = n.r + 5; attrs.y = 4; attrs["text-anchor"] = "start"; break;
            case "left": attrs.x = -n.r - 5; attrs.y = 4; attrs["text-anchor"] = "end"; break;
            default: attrs.y = n.r + 12; attrs["text-anchor"] = "middle";
          }
          grp.appendChild(svgEl("text", attrs));
        }

        const describe = () => {
          const parts = [el("div", { class: "ent-tip-kind", text: ENTITY_KIND_LABEL[n.kind] || n.kind }),
            el("div", { text: n.label })];
          if (n.sub) parts.push(el("div", { text: n.sub }));
          if (n.status) parts.push(el("div", { text: `${n.status}${n.detail ? ": " + n.detail : ""}` }));
          parts.push(el("div", { text: `${n.degree} relationship${n.degree === 1 ? "" : "s"}` }));
          tip.replaceChildren(...parts);
        };
        const move = (ev) => {
          const box = wrap.getBoundingClientRect();
          tip.style.display = "block";
          tip.style.left = `${Math.min(ev.clientX - box.left + 12, box.width - 270)}px`;
          tip.style.top = `${ev.clientY - box.top + 12}px`;
        };
        grp.addEventListener("mouseenter", (ev) => {
          describe(); move(ev);
          for (const line of edgesOf[n.id] || []) line.classList.add("ent-edge-active");
        });
        grp.addEventListener("mousemove", move);
        grp.addEventListener("mouseleave", () => {
          tip.style.display = "none";
          for (const line of edgesOf[n.id] || []) line.classList.remove("ent-edge-active");
        });
        const pivot = () => { state.focus = state.focus === n.id ? null : n.id; render(); };
        grp.addEventListener("click", pivot);
        grp.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pivot(); } });
        svg.appendChild(grp);
      }
      wrap.appendChild(svg);
      wrap.appendChild(tip);

      // --- legend: families by color, kinds by shape, status by ring
      const shapeChip = (kind) => {
        const mini = svgEl("svg", { width: 18, height: 18, viewBox: "-9 -9 18 18", class: `ent-fam-${famOf[kind] || "asset"}` });
        mini.appendChild(entityShape(kind, 6));
        return el("span", { class: "ent-legend-item" }, mini, el("span", { text: ENTITY_KIND_LABEL[kind] || kind }));
      };
      const ringChip = (status, text) => {
        const mini = svgEl("svg", { width: 18, height: 18, viewBox: "-9 -9 18 18", class: `ent-fam-asset ent-status-${status}` });
        mini.appendChild(svgEl("circle", { r: 4, class: "ent-node-shape" }));
        mini.appendChild(svgEl("circle", { r: 7, class: "ent-status-ring" }));
        return el("span", { class: "ent-legend-item" }, mini, el("span", { text }));
      };
      const legend = el("div", { class: "ent-legend" },
        ...kinds.map((k) => shapeChip(k.kind)),
        ringChip("warning", "needs attention"),
        ringChip("critical", "critical"));

      const shown = {};
      for (const n of g.nodes) shown[n.kind] = (shown[n.kind] || 0) + 1;
      const title = state.focus && byID[state.focus]
        ? `Around ${byID[state.focus].label} (${g.nodes.length} entities, ${g.edges.length} relationships)`
        : `Entity map (${g.nodes.length} entities, ${g.edges.length} relationships)`;

      const notes = [];
      notes.push(el("p", { class: "meta", text: "Color is the family (blue: what you own, orange: what's wrong with it, green: what you decided about it), shape is the kind, a ring is status, and size is how many things the entity touches. Click any entity to pivot the map around it; click it again to go back to the whole fleet." }));
      notes.push(el("p", { class: "meta", text: "A package earns a place only when it is vulnerable, denied, shadow AI, or a licensed product; a certificate only when it is expiring or expired; an extension only when it is risky or on more than one host. Otherwise this would be thousands of packages and answer nothing." }));
      if (g.edges.some((e) => e.kind === "indirect")) {
        notes.push(el("p", { class: "meta", text: "Dotted lines are indirect: the entity that joined those two is filtered out of this view, so the path is shown contracted rather than dropped. Turn its kind back on to see the real hops." }));
      }
      if (g.omitted) {
        notes.push(el("p", { class: "meta", text: `${g.omitted} lower-degree entities were left out to keep the map readable. Filter to a kind, or focus an entity, to see them.` }));
      }

      const parts = [el("h2", { text: title }), filters, legend, wrap, ...notes];
      if (state.focus && byID[state.focus]) parts.push(entityDetail(byID[state.focus], g.relations || [], (id) => { state.focus = id; render(); }));
      if (state.table) parts.push(entityTable(g, (id) => { state.focus = id; render(); }));
      card.replaceChildren(...parts);
    }

    await render();
  }

  // entityDetail is the focused entity's own panel: what it is, and
  // every relationship it has, in words.
  function entityDetail(node, relations, onPivot) {
    const head = el("div", {},
      el("h3", { text: node.label }),
      el("p", { class: "meta", text: [ENTITY_KIND_LABEL[node.kind] || node.kind, node.sub].filter(Boolean).join(" · ") }));
    if (node.status) {
      head.appendChild(el("p", {}, el("span", { class: `ent-pill ent-pill-${node.status}`, text: node.status }),
        node.detail ? el("span", { text: " " + node.detail }) : null));
    }
    if (node.href) {
      const open = el("a", { class: "back-link", href: node.href, text: "Open this host →" });
      head.appendChild(el("p", {}, open));
    }
    const list = el("ul", { class: "ent-rel-list" });
    for (const r of relations) {
      const name = el("button", { type: "button", class: "ghost ent-rel-name", text: r.other.label });
      name.addEventListener("click", () => onPivot(r.other.id));
      list.appendChild(el("li", { class: "ent-rel" },
        el("span", { class: "ent-rel-kind", text: ENTITY_EDGE_LABEL[r.kind] || r.kind }),
        el("span", { class: "ent-rel-type", text: ENTITY_KIND_LABEL[r.other.kind] || r.other.kind }),
        el("span", {}, name, r.other.status ? el("span", { class: `ent-pill ent-pill-${r.other.status}`, text: r.other.status }) : null,
          r.other.sub ? el("span", { class: "meta", text: " " + r.other.sub }) : null)));
    }
    if (!relations.length) list.appendChild(el("li", { class: "ent-rel" }, el("span", { class: "meta", text: "No relationships in this view. Widen the hop count or turn more kinds back on." })));
    return el("div", { class: "ent-detail" }, head, list);
  }

  // entityTable is the table view of the same graph -- the
  // non-visual route to the same facts, and the reason the map's
  // colors never have to carry a name on their own.
  function entityTable(g, onPivot) {
    const rows = [...g.nodes].sort((a, b) => (b.degree - a.degree) || a.label.localeCompare(b.label));
    const body = rows.map((n) => {
      const name = el("button", { type: "button", class: "ghost", text: n.label });
      name.addEventListener("click", () => onPivot(n.id));
      return el("tr", {},
        el("td", {}, name),
        el("td", { text: ENTITY_KIND_LABEL[n.kind] || n.kind }),
        el("td", { text: n.sub || "" }),
        el("td", {}, n.status ? el("span", { class: `ent-pill ent-pill-${n.status}`, text: n.status }) : el("span", { class: "meta", text: "ok" })),
        el("td", { text: String(n.degree) }));
    });
    return el("div", { class: "ent-detail" },
      el("h3", { text: "Every entity in this view" }),
      el("table", { class: "ent-table" },
        el("thead", {}, el("tr", {}, el("th", { text: "Entity" }), el("th", { text: "Kind" }), el("th", { text: "Detail" }), el("th", { text: "Status" }), el("th", { text: "Links" }))),
        el("tbody", {}, ...body)));
  }

  async function showCompliance() {
    const heading = el(
      "div", { class: "section-heading" },
      el("h1", { text: "Compliance" }),
      el("span", { class: "meta", text: "Posture, vulnerabilities, and software allow/deny lists, rolled up fleet-wide" })
    );

    const summarySlot = el("div", {});
    const rulesFormSlot = el("div", {});
    const rulesListSlot = el("div", {});
    const sprawlSlot = el("div", {});
    app.replaceChildren(heading, summarySlot, rulesFormSlot, rulesListSlot, sprawlSlot, scannerImportCard(), breachCard());
    sprawlCard().then((card) => sprawlSlot.replaceChildren(card));

    // Framework selector: every built-in framework scores the same
    // signals, so switching just re-asks the summary with ?framework=.
    let frameworks = [];
    try { frameworks = await api("/api/compliance/frameworks"); } catch (err) { /* selector simply won't render */ }
    const select = el("select", {}, ...frameworks.map((f) => el("option", { value: f.id, text: `${f.name} (${f.checks} checks)` })));
    const selectorRow = frameworks.length ? el("div", { class: "editor-row" }, el("label", { text: "Framework" }), select) : null;

    async function renderSummary(frameworkID) {
      try {
        const summary = await api(`/api/compliance/summary${frameworkID ? `?framework=${encodeURIComponent(frameworkID)}` : ""}`);
        const stats = el(
          "div", { class: "stat-grid" },
          el("div", { class: "stat-card" }, el("div", { class: "stat-value", text: `${summary.average_score}%` }), el("div", { class: "stat-label", text: "Average score" })),
          el("div", { class: "stat-card" }, el("div", { class: "stat-value", text: String(summary.fully_compliant) }), el("div", { class: "stat-label", text: "Fully compliant hosts" })),
          el("div", { class: "stat-card" }, el("div", { class: "stat-value", text: String(summary.total_hosts) }), el("div", { class: "stat-label", text: "Total hosts" }))
        );
        const checkRows = (summary.checks || []).map((c) =>
          el("li", { class: "policy-row" },
            el("span", { class: "policy-name", text: c.id }),
            el("span", { class: "policy-condition", text: c.description }),
            el("span", { class: `posture-badge ${c.failing === 0 ? "posture-good" : c.failing * 2 >= summary.total_hosts ? "posture-bad" : "posture-warn"}`, text: c.failing === 0 ? "all pass" : `${c.failing} failing` })));
        const hostRows = (summary.hosts || []).map((h) =>
          el("li", { class: "policy-row" },
            el("a", { href: `#/host/${encodeURIComponent(h.host)}`, class: "policy-name", text: h.host }),
            complianceScoreBadge(h.score)
          )
        );
        summarySlot.replaceChildren(
          el("div", { class: "fact-card" }, el("h2", { text: `${summary.framework} -- fleet summary` }), selectorRow, el("p", { class: "meta", text: summary.description || "" }), stats),
          el("div", { class: "fact-card" }, el("h2", { text: "Checks" }), checkRows.length ? el("ul", { class: "policy-list" }, ...checkRows) : el("p", { text: "No checks." })),
          el("div", { class: "fact-card" }, el("h2", { text: "Per-host scores" }), hostRows.length ? el("ul", { class: "policy-list" }, ...hostRows) : el("p", { text: "No hosts yet." }))
        );
      } catch (err) {
        summarySlot.replaceChildren(el("div", { class: "fact-card" }, el("p", { text: `Couldn't load compliance summary: ${err.message}` })));
      }
    }
    select.addEventListener("change", () => renderSummary(select.value));
    await renderSummary(frameworks.length ? frameworks[0].id : "");

    async function refreshRules() {
      try {
        const rules = await api("/api/software-rules");
        const list = rules.length
          ? el("ul", { class: "policy-list" }, ...rules.map((r) =>
              softwareRuleRow(r, async (target) => {
                if (!confirm(`Delete software rule "${target.name}"?`)) return;
                try { await api(`/api/software-rules/${target.id}`, { method: "DELETE" }); refreshRules(); }
                catch (err) { alert(`Couldn't delete: ${err.message}`); }
              })
            ))
          : el("p", { text: "No software rules yet." });
        rulesListSlot.replaceChildren(el("div", { class: "fact-card" }, el("h2", { text: `Software rules (${rules.length})` }), list));
      } catch (err) {
        rulesListSlot.replaceChildren(el("div", { class: "fact-card" }, el("p", { text: `Couldn't load software rules: ${err.message} -- managing rules requires an admin API token.` })));
      }
    }
    rulesFormSlot.replaceChildren(el("div", { class: "fact-card" }, softwareRuleForm(refreshRules)));
    await refreshRules();
  }

  // askHistory persists across navigation (module-level, not per-render)
  // so switching tabs and coming back to Ask Muster doesn't lose the
  // conversation -- purely client-side display state, not synced with
  // the server (the server's own record of every question+answer is the
  // audit log, GET /api/audit, which is the source of truth).
  const askHistory = [];

  function askTurn(question, answerNode) {
    return el(
      "div", { class: "ask-turn" },
      el("div", { class: "ask-question" }, el("strong", { text: "You: " }), question),
      el("div", { class: "ask-answer" }, el("strong", { text: "Muster: " }), answerNode)
    );
  }

  async function showAskMuster() {
    const heading = el(
      "div", { class: "section-heading" },
      el("h1", { text: "Ask Muster" }),
      el("span", { class: "meta", text: "Natural-language questions over your real fleet data -- every question and answer is recorded to the audit log (governed AI, not a generic chatbot)." })
    );

    const log = el("div", { class: "ask-log" });
    for (const turn of askHistory) log.appendChild(askTurn(turn.question, turn.answer));

    const questionInput = el("textarea", { class: "ask-input", rows: "2", placeholder: "e.g. Which prod hosts have known vulnerabilities? Any shadow AI detections I should know about?" });
    const sendBtn = el("button", { type: "submit", text: "Ask" });
    const statusMsg = el("span", { class: "save-msg" });
    const form = el("form", { class: "ask-form" }, questionInput, sendBtn, statusMsg);

    app.replaceChildren(heading, el("div", { class: "fact-card ask-card" }, log, form));
    log.scrollTop = log.scrollHeight;

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const question = questionInput.value.trim();
      if (!question) return;
      questionInput.value = "";
      sendBtn.disabled = true;
      statusMsg.textContent = "Thinking…";

      const thinking = el("em", { text: "…" });
      const turnNode = askTurn(question, thinking);
      log.appendChild(turnNode);
      log.scrollTop = log.scrollHeight;

      try {
        const { answer } = await api("/api/ask", { method: "POST", body: { question } });
        thinking.replaceWith(document.createTextNode(answer));
        askHistory.push({ question, answer });
        statusMsg.textContent = "";
      } catch (err) {
        thinking.replaceWith(el("span", { class: "ask-error", text: err.message }));
        statusMsg.textContent = "";
      } finally {
        sendBtn.disabled = false;
        log.scrollTop = log.scrollHeight;
      }
    });
  }

  function router() {
    const hash = location.hash || "#/";
    const hostMatch = hash.match(/^#\/host\/(.+)$/);
    if (hostMatch) {
      showHostDetail(decodeURIComponent(hostMatch[1]));
    } else if (hash === "#/board") {
      showBoard();
    } else if (hash === "#/fleet") {
      showFleet();
    } else if (hash === "#/agents") {
      showAgents();
    } else if (hash === "#/entities") {
      showEntities();
    } else if (hash === "#/compliance") {
      showCompliance();
    } else if (hash === "#/ask") {
      showAskMuster();
    } else if (hash === "#/docs") {
      showDocs();
    } else if (hash === "#/settings") {
      showSettings();
    } else {
      showDashboard();
    }
    updateSearchUI();
    updateNavUI();
  }

  function updateSearchUI() {
    const onDashboard = (location.hash || "#/") === "#/";
    searchForm.style.opacity = onDashboard ? "1" : "0.5";
    searchClear.hidden = !currentFilter;
  }

  function updateNavUI() {
    const hash = location.hash || "#/";
    const view = hash === "#/board" ? "board" : hash === "#/fleet" ? "fleet" : hash === "#/agents" ? "agents" : hash === "#/entities" ? "entities" : hash === "#/compliance" ? "compliance" : hash === "#/ask" ? "ask" : hash === "#/docs" ? "docs" : hash === "#/settings" ? "settings" : "hosts";
    for (const a of document.querySelectorAll(".view-tabs a")) {
      a.classList.toggle("active", a.dataset.view === view);
    }
  }

  searchForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const contains = searchContains.value.trim();
    if (!contains) return;
    currentFilter = { field: searchField.value, contains };
    if (location.hash !== "#/" && location.hash !== "") {
      location.hash = "#/";
    } else {
      showDashboard();
    }
    updateSearchUI();
  });

  searchClear.addEventListener("click", () => {
    currentFilter = null;
    searchContains.value = "";
    if ((location.hash || "#/") === "#/") showDashboard();
    updateSearchUI();
  });

  function refreshAuthStatus() {
    authStatus.textContent = getToken() ? "token set" : "";
  }

  authToggle.addEventListener("click", () => {
    authForm.hidden = !authForm.hidden;
    if (!authForm.hidden) authTokenInput.focus();
  });

  authForm.addEventListener("submit", (e) => {
    e.preventDefault();
    setToken(authTokenInput.value.trim());
    authTokenInput.value = "";
    authForm.hidden = true;
    refreshAuthStatus();
    router();
  });

  authClear.addEventListener("click", () => {
    setToken("");
    authTokenInput.value = "";
    refreshAuthStatus();
    router();
  });

  refreshAuthStatus();

  // OAuth dashboard login (internal/oauth) -- GET /api/auth/me tells
  // us whether the server has -oauth-* configured at all, and, if
  // this browser carries a valid session cookie, who as. Purely
  // additive to the bearer-token flow above: a signed-in session lets
  // requireRole/requireRoleStrict pass without a token in the Auth
  // box, but the token box still works exactly as before for scripts
  // and anyone who'd rather paste a key.
  async function loadOAuthStatus() {
    let info;
    try {
      const resp = await fetch("/api/auth/me");
      info = await resp.json();
    } catch {
      return;
    }
    if (!info || !info.oauth_enabled) {
      oauthStatus.hidden = true;
      oauthStatus.replaceChildren();
      return;
    }
    oauthStatus.hidden = false;
    if (info.authenticated) {
      const who = el("span", { text: `Signed in as ${info.email} (${info.role})` });
      const logout = el("button", { type: "button", class: "ghost", text: "Sign out" });
      logout.addEventListener("click", async () => {
        try {
          await fetch("/api/auth/logout", { method: "POST" });
        } catch {
          // best-effort -- the cookie is also cleared client-side by the response
        }
        loadOAuthStatus();
      });
      oauthStatus.replaceChildren(who, logout);
    } else {
      const login = el("a", { href: "/api/auth/login", text: "Sign in" });
      oauthStatus.replaceChildren(login);
    }
  }
  loadOAuthStatus();

  window.addEventListener("hashchange", router);
  router();

  pollTimer = setInterval(() => {
    // Only the plain hosts dashboard auto-refreshes -- the board is
    // excluded so a background re-render can't interrupt an in-progress
    // drag, and host detail already had its own reasons to stay out of
    // this before the board existed.
    if ((location.hash || "#/") === "#/") showDashboard();
  }, POLL_MS);
  window.addEventListener("beforeunload", () => clearInterval(pollTimer));
})();
