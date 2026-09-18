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
      headers["Content-Type"] = "application/json";
      fetchOpts.body = JSON.stringify(opts.body ?? {});
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
            el("strong", { text: `${f.package} ${f.installed_version}` }),
            ` — ${f.cve}: ${f.description}`
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
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "New policy rule" }),
      nameInput, kindSelect, thresholdInput, categoryInput, groupInput, remediateSelect, remediateArgInput,
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
    return form;
  }

  function policyRow(rule, onDelete) {
    const parts = [
      el("span", { class: "policy-name", text: rule.name }),
      el("span", { class: "policy-scope", text: rule.group ? `group: ${rule.group}` : "all hosts" }),
      el("span", { class: "policy-condition", text: ruleSummary(rule) }),
    ];
    if (rule.auto_remediate) {
      parts.push(el("span", { class: "tag-pill", text: `auto: ${rule.auto_remediate}${rule.auto_remediate_arg ? " " + rule.auto_remediate_arg : ""}` }));
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
    const body = el("div", { class: "posture-body" }, riskBadge(r.score, r.level),
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
    return el("div", { class: "fact-card" },
      el("h2", { text: "Reports & exports" }),
      el("p", { class: "meta", text: "The executive report opens as a print-ready page (use your browser's Print / Save as PDF). CSV exports carry the same numbers the dashboard shows. Audit export needs an admin credential." }),
      el("div", { class: "editor-row" },
        btn("Executive report", "/api/reports/executive", "", true),
        btn("Compliance CSV", "/api/reports/compliance.csv", `muster-compliance-${today}.csv`),
        btn("Risk CSV", "/api/reports/risk.csv", `muster-risk-${today}.csv`),
        btn("Vulnerabilities CSV", "/api/reports/vulnerabilities.csv", `muster-vulnerabilities-${today}.csv`),
        btn("Audit CSV", "/api/reports/audit.csv", `muster-audit-${today}.csv`),
        msg));
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
      statCard("Risky browser extensions", summary.total_risky_extensions || 0, summary.total_risky_extensions > 0 ? "stat-warn" : "")
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

    const nodes = [heading, stats, trendSlot, riskSlot, benchSlot, reportsCard(), platformCard, policiesFormSlot, policiesListSlot, discoveredSlot];

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

    app.replaceChildren(heading, form, revealSlot, listSlot, downloadsCard(), airgapImportCard());
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

  // siemForwardingEditor is the SIEM Forwarding card's edit form --
  // PATCH /api/settings, live (no restart) via internal/siemforward.Dynamic,
  // persisted via internal/settingsstore when the server was started
  // with a data dir. GET /api/settings never returns the HEC URL or
  // token (see settingsSIEM), so unlike groupEditor/tagEditor this
  // can't prefill from the current value -- changing anything means
  // retyping both fields, same "all-or-nothing pair" the -siem-hec-*
  // flags themselves enforce.
  function siemForwardingEditor(s) {
    const urlInput = el("input", { type: "text", placeholder: "https://splunk.example.com:8088" });
    const tokenInput = el("input", { type: "password", placeholder: "HEC token" });
    const disableBox = el("input", { type: "checkbox" });
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "HEC URL" }), urlInput,
      el("label", { text: "HEC token" }), tokenInput,
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
        if (!url || !token) { msg.textContent = "Error: HEC URL and token must both be set together"; return; }
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
    const modelInput = el("input", { type: "text", placeholder: "claude-opus-5 (default)", value: s.ask_muster.model || "" });
    const keyInput = el("input", { type: "password", placeholder: s.ask_muster.configured ? "leave blank to keep current key" : "sk-ant-..." });
    const disableBox = el("input", { type: "checkbox" });
    const msg = el("span", { class: "save-msg" });
    const form = el(
      "form",
      { class: "editor-row" },
      el("label", { text: "Model" }), modelInput,
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
        if (!key && !s.ask_muster.configured) { msg.textContent = "Error: an API key is required to enable Ask Muster"; return; }
        if (key) body.ai_api_key = key;
        body.ai_model = model;
        if (Object.keys(body).length === 0) { msg.textContent = "Nothing to save"; return; }
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
      ["Model", s.ask_muster.model || null],
    ], askMusterEditor(s));

    const webhooks = settingsTable("Webhooks", [
      ["Configured", boolLabel(s.webhooks.configured)],
      ["Count", s.webhooks.count],
    ]);

    const siem = settingsCardWithForm("SIEM forwarding", [
      ["Configured", boolLabel(s.siem.configured)],
      ["Backend", s.siem.backend || null],
    ], siemForwardingEditor(s));

    app.replaceChildren(heading, general, auth, vulnFeed, askMuster, webhooks, siem);
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

  async function showCompliance() {
    const heading = el(
      "div", { class: "section-heading" },
      el("h1", { text: "Compliance" }),
      el("span", { class: "meta", text: "Posture, vulnerabilities, and software allow/deny lists, rolled up fleet-wide" })
    );

    const summarySlot = el("div", {});
    const rulesFormSlot = el("div", {});
    const rulesListSlot = el("div", {});
    app.replaceChildren(heading, summarySlot, rulesFormSlot, rulesListSlot);

    try {
      const summary = await api("/api/compliance/summary");
      const stats = el(
        "div", { class: "stat-grid" },
        el("div", { class: "stat-card" }, el("div", { class: "stat-value", text: `${summary.average_score}%` }), el("div", { class: "stat-label", text: "Average score" })),
        el("div", { class: "stat-card" }, el("div", { class: "stat-value", text: String(summary.fully_compliant) }), el("div", { class: "stat-label", text: "Fully compliant hosts" })),
        el("div", { class: "stat-card" }, el("div", { class: "stat-value", text: String(summary.total_hosts) }), el("div", { class: "stat-label", text: "Total hosts" }))
      );
      const hostRows = (summary.hosts || []).map((h) =>
        el("li", { class: "policy-row" },
          el("a", { href: `#/host/${encodeURIComponent(h.host)}`, class: "policy-name", text: h.host }),
          complianceScoreBadge(h.score)
        )
      );
      summarySlot.replaceChildren(
        el("div", { class: "fact-card" }, el("h2", { text: `${summary.framework} -- fleet summary` }), stats),
        el("div", { class: "fact-card" }, el("h2", { text: "Per-host scores" }), hostRows.length ? el("ul", { class: "policy-list" }, ...hostRows) : el("p", { text: "No hosts yet." }))
      );
    } catch (err) {
      summarySlot.replaceChildren(el("div", { class: "fact-card" }, el("p", { text: `Couldn't load compliance summary: ${err.message}` })));
    }

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
    const view = hash === "#/board" ? "board" : hash === "#/fleet" ? "fleet" : hash === "#/agents" ? "agents" : hash === "#/compliance" ? "compliance" : hash === "#/ask" ? "ask" : hash === "#/docs" ? "docs" : hash === "#/settings" ? "settings" : "hosts";
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
