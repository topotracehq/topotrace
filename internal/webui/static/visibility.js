/*******************************************************************************
 * @file         visibility.js
 * @brief        Part of the Muster static module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

"use strict";
window.MusterVisibility = function ({ api, el, app, timeAgo, workspaceUI }) {
  let generation = 0;
  const label = value => (value || "unknown").replaceAll("_", " ");
  const categoryLabel = value => ({system_summary:"Operating system",installed_software:"Installed software",running_services:"Services",firewall_av_status:"Firewall",patch_update_status:"Pending updates"}[value] || label(value));
  function changeValue(value) {
    if (!value) return "—";
    // Render the store's simple package-list representation without exposing Go
    // formatting. Keep all other evidence exactly as recorded.
    if (/^\[(map\[name:[^\]\s]+ version:[^\]\s]+\]\s*)+\]$/.test(value))
      return [...value.matchAll(/map\[name:([^\]\s]+) version:([^\]\s]+)\]/g)].map(m => `${m[1]} ${m[2]}`).join("\n");
    return value;
  }
  const stamp = value => !value || value.startsWith("0001-") ? "Never recorded" : `${new Date(value).toLocaleString()} (${timeAgo(value)})`;
  const badge = state => el("span", { class: `visibility-badge visibility-${state}`, text: label(state) });
  function card(title, ...nodes) { return el("section", { class: "fact-card" }, el("h2", { text: title }), ...nodes); }
  function table(headers, rows) {
    return el("div", { class: "visibility-table-wrap" }, el("table", { class: "visibility-table" },
      el("thead", {}, el("tr", {}, ...headers.map(text => el("th", { scope: "col", text })))),
      el("tbody", {}, ...rows.map(cells => el("tr", {}, ...cells.map(cell => el("td", {}, typeof cell === "string" ? el("span", { text: cell }) : cell)))))));
  }
  async function show(demo = false, scenario = "overview") {
    const id = ++generation;
    const root = el("div", { class: "visibility-page" });
    app.replaceChildren(root);
    root.appendChild(el("h1", { text: "Device visibility" }));
    root.appendChild(el("p", {class:"page-intro",text:"Follow device changes, understand reporting health, and review discoveries."}));
    const nav = el("div", { class: "visibility-toolbar" },
      el("a", { href: "#/visibility", class: "ghost", text: "Live inventory" }),
      el("a", { href: "#/visibility/demo", class: "ghost", text: "Demo showcase" }));
    const refresh = el("button", { type: "button", text: demo ? "Reset demo" : "Refresh" });
    refresh.addEventListener("click", () => show(demo)); nav.appendChild(refresh); root.appendChild(nav);
    nav.appendChild(workspaceUI.presentationButton());
    nav.appendChild(workspaceUI.reportButton(demo));
    if(demo){const scenarios=el("select",{"aria-label":"Demo scenario"},...[["overview","Fleet overview"],["unauthorized","New unauthorized device"],["failed_change","Failed change"],["recovery","Verified recovery"]].map(([value,text])=>el("option",{value,text})));scenarios.value=scenario;scenarios.addEventListener("change",()=>show(true,scenarios.value));nav.appendChild(scenarios);}
    root.appendChild(el("p", { class: demo ? "visibility-demo" : "meta", text: demo
      ? "DEMO DATA — Six fictional devices and four sample discoveries. Reviews are temporary and reset with this page. No live inventory, notifications, or device actions are changed."
      : "Live evidence from your inventory and discovery reports. An unmatched device needs review; it is not automatically unauthorized." }));
    const loading = el("p", { text: "Loading device evidence…", role: "status" }); root.appendChild(loading);
    let data;
    try { data = await api(`/api/visibility${demo ? `?demo=1&scenario=${encodeURIComponent(scenario)}` : ""}`); }
    catch (err) { loading.textContent = err.message; return; }
    if (id !== generation || !root.isConnected) return;
    loading.remove();
    if(data.story){const story=el("section",{class:"demo-story"},el("h2",{text:`Demo: ${label(data.scenario)}`}),el("p",{text:data.story}));if(data.before&&data.after)story.appendChild(el("div",{class:"demo-story-grid"},...[["Before",data.before],["After",data.after]].map(([title,result])=>el("div",{},el("h3",{text:title}),badge(result.state),el("p",{text:result.detail}),el("p",{text:`Device: ${result.host}`})))));root.appendChild(story);}
    const stats = el("div", { class: "visibility-stats" });
    const renderStats = () => stats.replaceChildren(...[
      [data.agents.length, "Devices"], [data.agents.filter(a => a.state !== "healthy").length, "Agents needing attention"],
      [data.changes.length, "Recorded changes"], [data.assets.filter(a => a.state === "needs_review" || a.state === "unauthorized").length, "Discoveries needing attention"]
    ].map(([n, title]) => el("div", {}, el("strong", { text: String(n) }), el("span", { text: title }))));
    renderStats(); root.appendChild(stats);
    if (demo) root.appendChild(el("details", {class:"demo-guide"}, el("summary", {text:"Your three-minute demo · View walkthrough"}),
      el("ol", {}, ...[
        "Open Device history: show the web server upgrade, failed database service, and disabled laptop firewall.",
        "Open Agent health: compare healthy reporting, failed collection, a late laptop, and a missing branch device.",
        "Open Discovery review: match a managed address, review an unknown device, and explain the unauthorized appliance. Try a review; Reset demo restores the samples."
      ].map(text => el("li", { text })))));
    const tabs = el("div", { class: "visibility-toolbar", role: "group", "aria-label": "Visibility sections" });
    const content = el("div", {}); root.append(tabs, content);
    const hostNode = host => demo ? el("strong", { text: host }) : el("a", { href: `#/host/${encodeURIComponent(host)}`, text: host });
    function history() {
      const query = el("input", { type: "search", placeholder: "Search device, category, field, or value", "aria-label": "Search device history" });
      const category = el("select", { "aria-label": "Change category" }, el("option", { value: "", text: "All categories" }),
        ...[...new Set(data.changes.map(c => c.category))].sort().map(c => el("option", { value: c, text: categoryLabel(c) })));
      const rows = el("div", {}), count = el("p", { class: "meta", role: "status" });
      const draw = () => {
        const q = query.value.toLowerCase();
        const found = data.changes.filter(c => (!category.value || category.value === c.category) && [c.host,c.category,c.field,c.old_value,c.new_value].some(v => (v || "").toLowerCase().includes(q)));
        count.textContent = `${found.length} matching changes. ${data.history_limited ? "Showing a recent window: at most 100 changes per device and 1,000 total." : "Changes are recorded when collected values differ between reports."}`;
        rows.replaceChildren(found.length ? table(["When", "Device", "Category / field", "Before", "After"], found.map(c => [stamp(c.changed_at),hostNode(c.host),`${categoryLabel(c.category)} / ${label(c.field)}`,changeValue(c.old_value),changeValue(c.new_value)])) : el("p", { text: "No matching changes recorded." }));
      };
      query.addEventListener("input", draw); category.addEventListener("change", draw);
      content.replaceChildren(card("Device history", el("div", { class: "visibility-toolbar" }, query, category), count, rows)); draw();
      if(!demo)content.prepend(workspaceUI.savedControls("history",()=>({query:query.value,filter:category.value}),v=>{query.value=v.query;category.value=v.filter;if(category.selectedIndex<0)category.value="";draw();}));
    }
    function health() {
      const filter = el("select", { "aria-label": "Agent status" }, ...["all","attention","healthy","failing","missing","late","never","unknown"].map(s => el("option", { value: s, text: label(s) })));
      const rows = el("div", {});
      const draw = () => {
        const found = data.agents.filter(a => filter.value === "all" || (filter.value === "attention" ? a.state !== "healthy" : a.state === filter.value));
        rows.replaceChildren(found.length ? table(["Device", "Agent status", "Last report", "Collection evidence"], found.map(a => [hostNode(a.host),
          el("div", {}, badge(a.state), el("p", { text: a.detail }), el("small", { text: `Recorded failures: ${a.failures}; expected interval: ${a.expected_every_sec ? Math.round(a.expected_every_sec / 60) + " minutes" : "unknown"}` })),
          stamp(a.last_checkin), el("details", {}, el("summary", { text: `${a.coverage.percent}% coverage — ${a.coverage.verified}/${a.coverage.expected} categories current` }),
            ...a.coverage.evidence.map(e => el("p", { text: `${e.label}: ${e.state}. ${e.detail}` })))
        ])) : el("p", { text: "No devices match this status." }));
      };
      filter.addEventListener("change",draw);
      content.replaceChildren(card("Agent health",el("p", { class: "meta", text: "Agent health describes reporting. Evidence coverage describes what was collected. Neither guarantees that a device is secure. Missing means no report for over 24 hours; late means more than twice its usual interval." }),filter,rows)); draw();
      if(!demo)content.prepend(workspaceUI.savedControls("health",()=>({query:"",filter:filter.value}),v=>{filter.value=v.filter;if(filter.selectedIndex<0)filter.value="all";draw();}));
    }
    function discovery() {
      const filter = el("select", { "aria-label": "Discovery status" }, ...["all","needs_review","unauthorized","approved","managed"].map(s => el("option", { value:s, text:label(s) })));
      const rows = el("div", {});
      const draw = () => {
        const found = data.assets.filter(a => filter.value === "all" || a.state === filter.value);
        rows.replaceChildren(...found.map(a => {
          const item = card(a.address, badge(a.state), el("p", { text: `Ports: ${(a.open_ports || []).join(", ")} · Discovered by ${a.scanned_by}` }),
            el("p", { text: `First seen: ${stamp(a.discovered_at)}. Last seen: ${stamp(a.last_seen_at)}${a.stale ? ". Sighting is over 24 hours old or has no timestamp; current presence is unknown." : ""}` }));
          if (a.matched_host) item.appendChild(el("p", {}, "Matches managed device: ",hostNode(a.matched_host)));
          if (a.review) item.appendChild(el("p", { text: `Review: ${a.review.reason} — ${a.review.actor}, ${stamp(a.review.updated_at)}` }));
          if (a.state !== "managed") {
            const state = el("select", { "aria-label": `Review ${a.address}` }, ...["needs_review","approved","unauthorized"].map(s => el("option", { value:s,text:label(s) }))); state.value=a.state;
            const reason = el("input", { required:true,minlength:"3",maxlength:"1000",placeholder:"Reason for this decision", "aria-label": `Reason for ${a.address}` });
            const save = el("button", { type:"submit",text:demo ? "Try sample review" : "Save review (admin)" }), message = el("span", { role:"status" });
            const form=el("form", { class:"visibility-toolbar" },state,reason,save,message);
            form.addEventListener("submit",async event => {
              event.preventDefault(); save.disabled=true;
              try {
                if (reason.value.trim().length < 3) throw new Error("Please provide a reason of at least 3 characters.");
                const review=demo ? { state:state.value,reason:reason.value.trim(),actor:"demo-presenter",updated_at:new Date().toISOString() } : await api(`/api/discovered-assets/${encodeURIComponent(a.id)}/review`,{ method:"PUT",body:{state:state.value,reason:reason.value.trim()} });
                a.state=review.state; a.review=review; renderStats(); draw();
              } catch(err) { message.textContent=err.message; save.disabled=false; }
            }); item.appendChild(form);
          }
          return item;
        }));
        if (!found.length) rows.appendChild(el("p", { text:data.discovery_restricted ? "Discovery is available to accounts with fleet-wide access." : "No matching discovery reports. Submit a network discovery report to populate this list." }));
      };
      filter.addEventListener("change",draw);
      content.replaceChildren(card("Discovery review",el("p", { class:"meta",text:"Matches use device names and IPv4 addresses collected within 24 hours. Unknown equipment requires an operator decision. Reviews classify devices; they do not block network access or enroll agents." }),filter,rows)); draw();
      if(!demo)content.prepend(workspaceUI.savedControls("discovery",()=>({query:"",filter:filter.value}),v=>{filter.value=v.filter;if(filter.selectedIndex<0)filter.value="all";draw();}));
    }
    for (const [title,render] of [["Device history",history],["Agent health",health],["Discovery review",discovery]]) {
      const button=el("button",{type:"button",text:title,"aria-pressed":"false"});
      button.addEventListener("click",()=>{for(const b of tabs.children)b.setAttribute("aria-pressed",String(b===button));render();});tabs.appendChild(button);
    }
    (scenario==="unauthorized"?tabs.lastChild:tabs.firstChild).click();
    root.appendChild(el("p",{class:"meta",text:`Snapshot: ${stamp(data.generated_at)}. Use Refresh to fetch current evidence.`}));
  }
  return {show};
};
