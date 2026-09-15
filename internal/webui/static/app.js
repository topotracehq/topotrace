// Muster dashboard -- a small hash-routed SPA, no build step, no
// framework. Talks to the JSON API in internal/api over fetch().
(() => {
  "use strict";

  const app = document.getElementById("app");
  const searchForm = document.getElementById("search-form");
  const searchField = document.getElementById("search-field");
  const searchContains = document.getElementById("search-contains");
  const searchClear = document.getElementById("search-clear");

  const POLL_MS = 5000;
  // No server-side staleness/rule engine yet (see README "what's next")
  // -- this is purely a display heuristic: a host that hasn't reported
  // in this long shows a STALE badge.
  const STALE_MS = 24 * 60 * 60 * 1000;
  let currentFilter = null; // { field, contains } | null
  let pollTimer = null;
  // Board columns an operator has started typing into this session but
  // that have no host in them yet -- client-side only, not persisted.
  // A host dropped into one makes it "real" (its group is now set
  // server-side); an empty one goes away on reload. A dedicated
  // /api/groups endpoint to persist the known column list is a natural
  // next step, not v1.
  const extraGroups = new Set();

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
    if (opts && opts.method) {
      fetchOpts.method = opts.method;
      fetchOpts.headers = { "Content-Type": "application/json" };
      fetchOpts.body = JSON.stringify(opts.body ?? {});
    }
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
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = input.value.trim();
      if (!name) return;
      extraGroups.add(name);
      showBoard();
    });
    return el("div", { class: "board-add-column" }, form);
  }

  async function showBoard() {
    let hosts;
    try {
      hosts = await api("/api/hosts");
    } catch (err) {
      app.replaceChildren(el("div", { class: "error-banner", text: `Couldn't load hosts: ${err.message}` }));
      return;
    }

    if (hosts.length === 0 && extraGroups.size === 0) {
      app.replaceChildren(emptyState("no-hosts"));
      return;
    }

    const byGroup = new Map();
    const keys = new Set([""].concat([...extraGroups]));
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

  async function showHostDetail(name) {
    let payload;
    try {
      payload = await api(`/api/hosts/${encodeURIComponent(name)}`);
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
            isStale(host.last_cooked) ? el("span", { class: "stale-badge", text: "STALE" }) : null
          ),
          el("div", { class: "detail-meta", text: `Last reported ${timeAgo(host.last_cooked)} · first seen ${timeAgo(host.first_seen)}` })
        )
      ),
      groupEditor(host),
      tagEditor(host),
    ];

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

  function router() {
    const hash = location.hash || "#/";
    const hostMatch = hash.match(/^#\/host\/(.+)$/);
    if (hostMatch) {
      showHostDetail(decodeURIComponent(hostMatch[1]));
    } else if (hash === "#/board") {
      showBoard();
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
    const view = (location.hash || "#/") === "#/board" ? "board" : "hosts";
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
