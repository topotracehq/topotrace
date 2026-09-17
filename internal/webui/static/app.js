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

  async function showHostDetail(name) {
    let payload, posture, findings;
    try {
      [payload, posture, findings] = await Promise.all([
        api(`/api/hosts/${encodeURIComponent(name)}`),
        loadPosture(name),
        loadVulnerabilities(name),
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
    nodes.push(vulnerabilitiesCard(findings || []));

    if (!facts || facts.length === 0) {
      nodes.push(el("p", { text: "No facts recorded for this host yet." }));
    }
    for (const fact of facts || []) {
      const table = el("table", { class: "fact-table" });
      for (const [k, v] of Object.entries(fact.data).sort(([a], [b]) => a.localeCompare(b))) {
        const tr = el("tr");
        tr.appendChild(el("td", { text: titleCase(k) }));
        tr.appendChild(el("td", { text: formatValue(k, v) }));
        table.appendChild(tr);
      }
      nodes.push(el("div", { class: "fact-card" }, el("h2", { text: fact.category.replace(/_/g, " ") }), table));
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

  function policyRow(rule) {
    const parts = [
      el("span", { class: "policy-name", text: rule.name }),
      el("span", { class: "policy-scope", text: rule.group ? `group: ${rule.group}` : "all hosts" }),
      el("span", { class: "policy-condition", text: ruleSummary(rule) }),
    ];
    if (rule.auto_remediate) {
      parts.push(el("span", { class: "tag-pill", text: `auto: ${rule.auto_remediate}${rule.auto_remediate_arg ? " " + rule.auto_remediate_arg : ""}` }));
    }
    return el("li", { class: "policy-row" }, ...parts);
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
    const [policiesResult, auditResult] = await Promise.allSettled([api("/api/policies"), api("/api/audit?limit=20")]);
    const policies = policiesResult.status === "fulfilled" ? policiesResult.value : [];
    const audit = auditResult.status === "fulfilled" ? auditResult.value : null;

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
      statCard("Total findings", summary.total_vulnerability_findings, summary.total_vulnerability_findings > 0 ? "stat-warn" : "")
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

    const policiesList = policies.length
      ? el("ul", { class: "policy-list" }, ...policies.map(policyRow))
      : el("p", { text: "No policy rules configured yet. Create one with POST /api/policies (admin key required)." });
    const policiesCard = el("div", { class: "fact-card" }, el("h2", { text: `Policies (${policies.length})` }), policiesList);

    const nodes = [heading, stats, platformCard, policiesCard];

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
  };
  const PLATFORM_ORDER = ["linux", "windows", "macos", "android", "ios"];

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
      default: // android / ios -- no TCP one-liner, these use POST /api/mobile-report instead
        return [
          `Server URL:  ${location.protocol}//${location.host}/api/mobile-report`,
          `Host name:   ${enrollment.host}`,
          `Token:       ${token}`,
          "",
          enrollment.platform === "android"
            ? "Enter these three values in the Muster Android app's setup screen (agent/android/ -- build it in Android Studio first)."
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

  function revealPanel(enr, token) {
    const pre = el("pre", { class: "install-snippet", text: installSnippet(enr, token) });
    const copyBtn = el("button", { type: "button", text: "Copy" });
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pre.textContent);
        copyBtn.textContent = "Copied";
        setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
      } catch {
        // clipboard API can be unavailable (insecure context, permissions) --
        // the text is already selectable in the <pre>, so this is a soft failure
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
    } else if (hash === "#/docs") {
      showDocs();
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
    const view = hash === "#/board" ? "board" : hash === "#/fleet" ? "fleet" : hash === "#/agents" ? "agents" : hash === "#/compliance" ? "compliance" : hash === "#/docs" ? "docs" : "hosts";
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
