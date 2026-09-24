// Sandbox-only UI overlay. Does nothing unless the page is being served
// from sandbox.topotrace.org -- safe to ship in the real binary since
// this guard means it's inert everywhere else, including customer
// installs and your own dev/prod boxes.
(function () {
  if (location.hostname !== "sandbox.topotrace.org") return;

  var RESET_INTERVAL_MIN = 60;

  function secondsToNextReset() {
    var now = new Date();
    var next = new Date(now);
    next.setMinutes(0, 0, 0);
    next.setHours(next.getHours() + 1);
    return Math.max(0, Math.round((next - now) / 1000));
  }

  var watermark = document.createElement("div");
  watermark.id = "tt-sandbox-watermark";
  document.body.appendChild(watermark);

  var CTA_DISMISS_KEY = "tt-sandbox-cta-dismissed";
  var ctaDismissed = false;
  try { ctaDismissed = sessionStorage.getItem(CTA_DISMISS_KEY) === "1"; } catch (e) {}

  function tick() {
    var s = secondsToNextReset();
    var m = Math.floor(s / 60);
    var sec = s % 60;
    var ctaHtml = ctaDismissed ? "" :
      " &middot; <a href='mailto:michael@topotrace.com?subject=" +
      encodeURIComponent("TopoTrace design partner / feedback session") +
      "' id='tt-wm-cta' style='color:#fbbf24;pointer-events:auto;'>Contact the founder</a>" +
      " <a href='#' id='tt-wm-cta-dismiss' aria-label='Dismiss contact link' style='color:#94a3b8;pointer-events:auto;text-decoration:none;'>&times;</a>";
    watermark.innerHTML =
      "Sandbox &mdash; read-only demo data, resets in " +
      "<b>" + m + ":" + (sec < 10 ? "0" : "") + sec + "</b>" +
      " &middot; <a href='#' id='tt-wm-tour' style='color:#93c5fd;pointer-events:auto;'>Start guided tour</a>" +
      " &middot; <a href='https://topotrace.org/download' target='_blank' rel='noopener' style='color:#93c5fd;pointer-events:auto;'>Download Community</a>" +
      " &middot; <a href='https://topotrace.org' target='_blank' rel='noopener' style='color:#93c5fd;pointer-events:auto;'>topotrace.org</a>" +
      ctaHtml;
    var tourLink = document.getElementById("tt-wm-tour");
    if (tourLink) {
      tourLink.addEventListener("click", function (e) {
        e.preventDefault();
        if (window.__ttStartTour) window.__ttStartTour();
      });
    }
    var ctaDismissLink = document.getElementById("tt-wm-cta-dismiss");
    if (ctaDismissLink) {
      ctaDismissLink.addEventListener("click", function (e) {
        e.preventDefault();
        ctaDismissed = true;
        try { sessionStorage.setItem(CTA_DISMISS_KEY, "1"); } catch (err) {}
        tick();
      });
    }
  }
  tick();
  setInterval(tick, 1000);

  // ---- 1b. Hide account/bearer-token controls; offer Exit sandbox ----
  // A public evaluator should never see "Bearer token (master or an API
  // key)" -- that's an operator control, not a demo control, and it
  // invites exactly the confused "where do I get a token" question this
  // sandbox exists to avoid. Real deployments are untouched: this only
  // runs on sandbox.topotrace.org (see the hostname guard at the top of
  // this file).
  function hideAccountControls() {
    var authControl = document.querySelector(".auth-control");
    if (!authControl || authControl.dataset.ttReplaced) return;
    authControl.dataset.ttReplaced = "1";
    authControl.innerHTML = "";
    var exitLink = document.createElement("a");
    exitLink.href = "https://topotrace.org/";
    exitLink.className = "ghost";
    exitLink.textContent = "Exit sandbox";
    exitLink.style.textDecoration = "none";
    var aboutLink = document.createElement("a");
    aboutLink.href = "#/about";
    aboutLink.className = "ghost";
    aboutLink.textContent = "About this demo";
    aboutLink.style.marginLeft = "8px";
    aboutLink.style.textDecoration = "none";
    authControl.appendChild(exitLink);
    authControl.appendChild(aboutLink);
  }
  hideAccountControls();

  // ---- 1c. Promote Guided demo near the top of the sidebar ----------
  // The walkthrough (visibility/demo) starts out buried as a small link
  // in the sidebar footer. Give it a real, labeled entry near Today.
  function promoteGuidedDemo() {
    var firstSection = document.querySelector(".view-tabs .nav-section");
    if (!firstSection || document.getElementById("tt-guided-demo-link")) return;
    var link = document.createElement("a");
    link.href = "#/visibility/demo";
    link.id = "tt-guided-demo-link";
    link.dataset.view = "guided-demo";
    link.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M10 8.5v7l6-3.5-6-3.5Z"/></svg><span class="tab-label">Guided demo</span>';
    var firstLink = firstSection.querySelector("a");
    if (firstLink) {
      firstLink.insertAdjacentElement("afterend", link);
    } else {
      firstSection.appendChild(link);
    }
  }
  promoteGuidedDemo();
  new MutationObserver(promoteGuidedDemo).observe(document.body, { childList: true, subtree: true });

  var CALLOUTS = [
    {
      match: /^Agents?( Health)?$/i,
      html: '<span class="tt-icon">&#9432;</span><div>' +
            "<b>Agents aren't connectable here.</b> This sandbox is read-only " +
            "demo data seeded on a timer, so there's nothing live to check in " +
            "against. In a real deployment, install the agent on a host and " +
            "point it at your server's ingest port (9090) with " +
            "<code>--topotrace-host / --topotrace-port</code>, or run the " +
            "bundled demo agent (<code>go run ./cmd/demoagent</code>) to see " +
            "one report in.</div>"
    },
    {
      match: /^(Discovery( ?&? ?Deployment)?)$/i,
      html: '<span class="tt-icon">&#9432;</span><div>' +
            "<b>Network discovery is disabled on this box.</b> This sandbox " +
            "can't be allowed to scan the network it's running on. In a real " +
            "deployment this runs a bounded local scan and stages results for " +
            "review before anything's added to inventory.</div>"
    },
    {
      match: /^Integration Health$/i,
      html: '<span class="tt-icon">&#9432;</span><div>' +
            "<b>No integrations are wired up here.</b> Slack/Teams/Jira/" +
            "ServiceNow/SIEM forwarding all need real credentials, which " +
            "aren't configured on a public demo box on purpose.</div>"
    },
    {
      match: /^Settings$/i,
      html: '<span class="tt-icon">&#9432;</span><div>' +
            "<b>Settings are locked in this sandbox.</b> Plugin upload, " +
            "OAuth/SSO, and notification config all require write/admin " +
            "access, which stays off for a public read-only demo.</div>"
    },
    {
      match: /^License( and seat usage)?$/i,
      html: '<span class="tt-icon">&#9432;</span><div>' +
            "<b>License and seat usage is admin-only.</b> It reports active " +
            "directory seats against a configured <code>-licensed-seats</code> " +
            "ceiling, with trend history and a near-limit alert -- reporting " +
            "only, it never blocks a login. Locked here along with the rest " +
            "of Administration &amp; help for the same read-only reason as " +
            "Settings.</div>"
    }
  ];

  var seeded = new WeakSet();

  function tryInsertCallouts() {
    var headings = document.querySelectorAll("h1, h2, h3, [role='heading'], button, a");
    headings.forEach(function (el) {
      if (seeded.has(el)) return;
      var text = (el.textContent || "").trim();
      if (!text || text.length > 40) return;
      for (var i = 0; i < CALLOUTS.length; i++) {
        if (CALLOUTS[i].match.test(text)) {
          seeded.add(el);
          if (el.tagName === "BUTTON" || el.tagName === "A") continue;
          var box = document.createElement("div");
          box.className = "tt-sandbox-callout";
          box.innerHTML = CALLOUTS[i].html;
          if (el.parentNode) {
            el.parentNode.insertBefore(box, el.nextSibling);
          }
        }
      }
    });
  }

  tryInsertCallouts();
  var observer = new MutationObserver(function () {
    tryInsertCallouts();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // ---- 3b. Guided tour: accessible dialog, focus-managed, 5 steps ----
  var TOUR_STEPS = [
    {
      hash: "#/fleet",
      expect: /^Fleet$/,
      title: "Fleet overview",
      body: "This is the whole fleet's posture at a glance: average score, hosts with vulnerabilities, stale reporting, and pending approvals. In your own deployment this is the page you'd check first every morning.",
      spotlight: ".stat-grid"
    },
    {
      hash: "#/host/db01.prod",
      expect: /^db01\.prod/,
      title: "A host with current evidence",
      body: "Every claim TopoTrace makes traces back to raw evidence an agent actually collected -- installed packages, patch status, certificates, disk usage -- not a guess. Expand a section below to see the underlying fact and when it was collected.",
      spotlight: ".evidence-details"
    },
    {
      hash: "#/work",
      expect: /^Work queue$/,
      title: "A meaningful finding",
      body: "Findings are prioritized by risk, not just listed. Each one names the affected host, the evidence behind it, and a recommended next step -- so the question is never just 'what's wrong', it's 'what do I do about it'.",
      spotlight: ".work-list"
    },
    {
      hash: "#/inbox",
      expect: /^Inbox$/,
      title: "A recorded change",
      body: "Remediation actions are tracked end to end: queued, delivered to the agent, and the result reported back -- success or failure. This inbox item is a failed change on db01.prod, exactly as an operator would see it.",
      spotlight: ".product-attention"
    },
    {
      hash: "#/reports",
      expect: /^Reports$/,
      title: "Executive report preview",
      body: "The same fleet data rolls up into a print-ready executive report -- posture trend, top risks, recent activity -- for the people who don't want to click through the dashboard. Try 'Preview sample report' below.",
      spotlight: ".tt-sandbox-report-actions"
    }
  ];
  var tourStep = -1;
  var tourPanel = null;
  var tourLauncher = null;
  var tourWaitToken = 0;

  function focusableIn(container) {
    return Array.prototype.filter.call(
      container.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'),
      function (el) { return el.offsetParent !== null; }
    );
  }

  function tourTrapKeydown(e) {
    if (!tourPanel) return;
    if (e.key === "Escape") { e.preventDefault(); tourExit(); return; }
    if (e.key !== "Tab") return;
    var focusables = focusableIn(tourPanel);
    if (!focusables.length) { e.preventDefault(); return; }
    var first = focusables[0], last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    else if (!tourPanel.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
  }

  function waitForStep(step, cb) {
    var token = ++tourWaitToken;
    var deadline = Date.now() + 4000;
    (function poll() {
      if (token !== tourWaitToken) return; // superseded by a newer navigation
      var h1 = document.querySelector("h1");
      var text = h1 ? (h1.textContent || "").trim() : "";
      if (step.expect.test(text) || Date.now() > deadline) { cb(); return; }
      setTimeout(poll, 60);
    })();
  }

  var tourSpotlit = null;
  function clearSpotlight() {
    if (tourSpotlit) { tourSpotlit.classList.remove("tt-tour-spotlight"); tourSpotlit = null; }
  }

  function applySpotlight(step) {
    clearSpotlight();
    if (!step.spotlight) return;
    var mySpotlightToken = tourWaitToken;
    var tries = 0;
    (function attempt() {
      if (mySpotlightToken !== tourWaitToken) return; // a newer step superseded this one
      var target = document.querySelector(step.spotlight);
      if (!target) {
        // A couple of these render their content asynchronously after the
        // route's own heading is already up, so give it a little more time
        // before giving up -- the modal still works fine without a highlight.
        if (tries++ < 6) setTimeout(attempt, 200);
        return;
      }
      target.classList.add("tt-tour-spotlight");
      tourSpotlit = target;
      if (target.scrollIntoView) target.scrollIntoView({ block: "center", behavior: "smooth" });
    })();
  }

  function tourRender() {
    if (!tourPanel) return;
    // Defensive: re-attach if an app.js re-render ever detached the panel.
    if (!document.body.contains(tourPanel)) document.body.appendChild(tourPanel);
    var step = TOUR_STEPS[tourStep];
    applySpotlight(step);
    var n = tourStep + 1, total = TOUR_STEPS.length;
    tourPanel.innerHTML =
      '<p class="tt-tour-progress" aria-label="Step ' + n + ' of ' + total + '">' + n + " of " + total + "</p>" +
      '<h2 id="tt-tour-title" tabindex="-1">' + step.title + "</h2>" +
      '<p id="tt-tour-desc">' + step.body + "</p>" +
      '<div class="tt-tour-actions">' +
      '<button type="button" id="tt-tour-exit" class="tt-tour-exit">Exit tour</button>' +
      '<span style="flex:1"></span>' +
      '<button type="button" id="tt-tour-back"' + (tourStep === 0 ? " disabled" : "") + '>Back</button>' +
      '<button type="button" id="tt-tour-next">' + (tourStep === total - 1 ? "Finish" : "Next") + "</button>" +
      "</div>";
    document.getElementById("tt-tour-exit").addEventListener("click", tourExit);
    document.getElementById("tt-tour-back").addEventListener("click", function () { tourGo(tourStep - 1); });
    document.getElementById("tt-tour-next").addEventListener("click", function () {
      if (tourStep === total - 1) { tourFinish(); return; }
      tourGo(tourStep + 1);
    });
    var heading = document.getElementById("tt-tour-title");
    if (heading) heading.focus({ preventScroll: true });
    if (tourLive) tourLive.textContent = "Step " + n + " of " + total + ": " + step.title;
  }

  function tourGo(i) {
    tourStep = i;
    var step = TOUR_STEPS[i];
    location.hash = step.hash;
    waitForStep(step, tourRender);
  }

  function applyInert(on) {
    var shell = document.querySelector(".sidebar"), main = document.querySelector("#app") || document.querySelector("main");
    [shell, main].forEach(function (node) {
      if (!node) return;
      if (on) node.setAttribute("inert", ""); else node.removeAttribute("inert");
    });
    var topbar = document.querySelector(".topbar");
    if (topbar) { if (on) topbar.setAttribute("inert", ""); else topbar.removeAttribute("inert"); }
  }

  var tourLive = null;
  var tourPending = false;
  function tourExit() {
    if (!tourPanel && !tourPending) return;
    tourStep = -1;
    tourWaitToken++; // invalidate any in-flight waitForStep poll
    tourPending = false;
    document.removeEventListener("keydown", tourTrapKeydown, true);
    applyInert(false);
    clearSpotlight();
    if (tourPanel) { tourPanel.remove(); tourPanel = null; }
    if (tourLauncher && document.body.contains(tourLauncher)) tourLauncher.focus();
    tourLauncher = null;
  }

  // Selecting Finish (vs. Exit/Escape) ends on a different page than the
  // tour was launched from, so the original launcher button is usually
  // gone from the DOM. Send focus to the destination page's own heading
  // instead of leaving it on document.body.
  function tourFinish() {
    if (!tourPanel && !tourPending) return;
    tourStep = -1;
    tourWaitToken++;
    tourPending = false;
    document.removeEventListener("keydown", tourTrapKeydown, true);
    applyInert(false);
    clearSpotlight();
    if (tourPanel) { tourPanel.remove(); tourPanel = null; }
    tourLauncher = null;
    var h = document.querySelector("h1");
    if (h) {
      if (!h.hasAttribute("tabindex")) h.setAttribute("tabindex", "-1");
      h.focus({ preventScroll: true });
    }
  }

  function tourMount() {
    tourPanel = document.createElement("section");
    tourPanel.id = "tt-tour-panel";
    tourPanel.setAttribute("role", "dialog");
    tourPanel.setAttribute("aria-modal", "true");
    tourPanel.setAttribute("aria-labelledby", "tt-tour-title");
    tourPanel.setAttribute("aria-describedby", "tt-tour-desc");
    document.body.appendChild(tourPanel);
    if (!tourLive) {
      tourLive = document.createElement("div");
      tourLive.setAttribute("aria-live", "polite");
      tourLive.className = "tt-visually-hidden";
      document.body.appendChild(tourLive);
    }
    applyInert(true);
    document.addEventListener("keydown", tourTrapKeydown, true);
  }

  function tourStart() {
    if (tourPanel || tourPending) return;
    tourPending = true;
    tourLauncher = document.activeElement;
    tourStep = 0;
    var step = TOUR_STEPS[0];
    location.hash = step.hash;
    // Wait for the Fleet route to actually render before mounting the dialog,
    // applying inert to the app shell, or installing the focus trap -- doing
    // those synchronously raced the route render and could leave an empty,
    // effectively invisible dialog trapping Tab for up to 4s.
    waitForStep(step, function () {
      if (!tourPending) return; // tour was exited while we were waiting
      tourPending = false;
      tourMount();
      tourRender();
    });
  }
  window.__ttStartTour = tourStart;

  // ---- 3c. Persistent tour CTA + curated starting point on Today -----
  var todaySeeded = false;
  function tryInsertTodayCTA() {
    if (location.hash && location.hash !== "#/" && location.hash !== "#/home" && location.hash !== "") { todaySeeded = false; return; }
    if (todaySeeded) return;
    var intro = document.querySelector(".page-intro");
    if (!intro || !intro.parentNode) return;
    todaySeeded = true;
    var cta = document.createElement("div");
    cta.className = "tt-sandbox-callout";
    cta.style.background = "#eff6ff";
    cta.style.borderColor = "#93c5fd";
    cta.style.borderLeftColor = "#1d4ed8";
    cta.innerHTML =
      '<span class="tt-icon" style="color:#1d4ed8;">&#9654;</span><div><b>New here? Take the 3-minute tour.</b> ' +
      "It walks through the fleet overview, a host's evidence, a real finding, a recorded change, and the executive report — the fastest way to see what TopoTrace actually does." +
      '<div style="margin-top:8px;"><button type="button" id="tt-today-tour-btn">Take the 3-minute tour</button></div>' +
      '<p class="meta" style="margin-top:10px;"><b>Start here:</b> <a href="#/host/db01.prod">db01.prod</a> is the most at-risk seeded host — a stale, internet-adjacent database server with real CVE matches. Its ' +
      '<a href="#/work">related finding is in the Work queue</a>, and the change queued to fix it shows up in the <a href="#/inbox">Inbox</a>.</p></div>';
    intro.parentNode.insertBefore(cta, intro.nextSibling);
    var btn = document.getElementById("tt-today-tour-btn");
    if (btn) btn.addEventListener("click", tourStart);
  }
  tryInsertTodayCTA();
  new MutationObserver(tryInsertTodayCTA).observe(document.body, { childList: true, subtree: true });
  window.addEventListener("hashchange", function () { setTimeout(tryInsertTodayCTA, 50); });

  // ---- 3d. Label pending approvals as simulated ----------------------
  var approvalsSeeded = false;
  function tryInsertApprovalsNote() {
    var heading = Array.prototype.find.call(
      document.querySelectorAll("h2"),
      function (el) { return /^Pending approvals/.test((el.textContent || "").trim()); }
    );
    if (!heading || !heading.parentNode) { approvalsSeeded = false; return; }
    if (heading.parentNode.querySelector(".tt-approvals-note")) return;
    var note = document.createElement("p");
    note.className = "meta tt-approvals-note";
    note.textContent = "Approve/Reject here are live, simulated writes against this sandbox's seeded data -- they take effect immediately but reset with the rest of the demo fleet every hour. No real system is touched.";
    heading.insertAdjacentElement("afterend", note);
  }
  tryInsertApprovalsNote();
  new MutationObserver(tryInsertApprovalsNote).observe(document.body, { childList: true, subtree: true });

  // ---- 3e. Ask TopoTrace: sandbox-appropriate intro + simulated label -
  var askSeeded = false;
  function tryUpdateAskIntro() {
    var h1 = Array.prototype.find.call(document.querySelectorAll("h1"), function (el) { return (el.textContent || "").trim() === "Ask TopoTrace"; });
    if (!h1) { askSeeded = false; return; }
    var metaSpan = h1.parentNode && h1.parentNode.querySelector("span.meta");
    if (metaSpan && !askSeeded) {
      metaSpan.textContent = "Ask questions about the seeded demo fleet. In your own deployment, connect your preferred supported model and query your infrastructure evidence. Questions and responses can be retained in the audit log.";
      askSeeded = true;
    }
    document.querySelectorAll(".ask-log .evidence-answer").forEach(function (node) {
      if (node.dataset.ttSim) return;
      node.dataset.ttSim = "1";
      var tag = document.createElement("p");
      tag.className = "meta";
      tag.textContent = "Simulated demo answer, generated from the seeded fleet.";
      node.appendChild(tag);
    });
  }
  tryUpdateAskIntro();
  new MutationObserver(tryUpdateAskIntro).observe(document.body, { childList: true, subtree: true });

  // ---- 4b. A useful Report Builder in sandbox mode -------------------
  // /api/reports/executive already has a ?demo=1 mode (see
  // internal/api/reports.go's buildReport) that renders the print-ready
  // executive report from the same seeded synthetic fleet the visibility
  // walkthrough uses, independent of whatever collection/date filters
  // are on screen. That's exactly the "sample report" this callout
  // promises -- no separate PDF asset to maintain.
  var reportSeeded = false;
  function tryInsertReportBuilderCallout() {
    if (reportSeeded) return;
    var heading = Array.prototype.find.call(
      document.querySelectorAll("h1, h2, h3, [role='heading']"),
      function (el) { return (el.textContent || "").trim() === "Configure branded report"; }
    );
    if (!heading || !heading.parentNode) return;
    reportSeeded = true;
    var box = document.createElement("div");
    box.className = "tt-sandbox-callout";
    box.innerHTML =
      '<span class="tt-icon">&#9432;</span><div><b>Report creation is read-only in this public sandbox.</b> ' +
      'Preview a sample executive report or install TopoTrace Community to build reports from your own infrastructure.' +
      '<div class="tt-sandbox-report-actions" style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">' +
      '<button type="button" id="tt-report-preview">Preview sample report</button>' +
      '<button type="button" id="tt-report-pdf">Download sample PDF</button>' +
      '<a href="https://topotrace.org/download" target="_blank" rel="noopener" id="tt-report-install">Install Community</a>' +
      '</div></div>';
    heading.parentNode.insertBefore(box, heading.nextSibling);
    var openSample = function (thenPrint) {
      var w = window.open("/api/reports/executive?demo=1", "_blank");
      if (!w) return;
      if (thenPrint) {
        var tryPrint = function () {
          try { w.focus(); w.print(); } catch (e) {}
        };
        w.addEventListener ? w.addEventListener("load", tryPrint) : setTimeout(tryPrint, 1200);
      }
    };
    var previewBtn = document.getElementById("tt-report-preview");
    var pdfBtn = document.getElementById("tt-report-pdf");
    if (previewBtn) previewBtn.addEventListener("click", function () { openSample(false); });
    if (pdfBtn) pdfBtn.addEventListener("click", function () { openSample(true); });
  }
  var reportObserver = new MutationObserver(function () {
    tryInsertReportBuilderCallout();
  });
  reportObserver.observe(document.body, { childList: true, subtree: true });
  window.addEventListener("hashchange", function () {
    reportSeeded = false;
    setTimeout(tryInsertReportBuilderCallout, 50);
  });
  tryInsertReportBuilderCallout();

  // ---- 5. Friendlier message for auth-gated writes -------------------
  // Approvals, plan promotion, dynamic-group edits, and a few other
  // sensitive actions always require -auth-token (see requireRoleStrict
  // in internal/api/server.go), even in demo mode -- on purpose, so a
  // public sandbox can never accept a real write. The server's error
  // text ("this endpoint requires the server to be started with
  // -auth-token") is accurate but reads like a misconfiguration. Rewrite
  // it client-side, at the fetch layer, so it's friendly everywhere the
  // app surfaces api() errors without having to special-case every
  // button that can hit it.
  var origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (input, init) {
      return origFetch(input, init).then(function (res) {
        if (res.ok) return res;
        return res
          .clone()
          .json()
          .then(function (body) {
            if (
              body &&
              typeof body.error === "string" &&
              body.error.indexOf("-auth-token") !== -1
            ) {
              var friendly =
                "This is disabled on the public sandbox -- admin actions like approvals, " +
                "promotions, and remediation need a real -auth-token, which is deliberately " +
                "not set here. In your own deployment this works normally.";
              var patched = JSON.stringify(
                Object.assign({}, body, { error: friendly })
              );
              return new Response(patched, {
                status: res.status,
                statusText: res.statusText,
                headers: res.headers,
              });
            }
            return res;
          })
          .catch(function () {
            return res;
          });
      });
    };
  }
})();

// ---- 3. Click tracking (rides on Caddy's access log) ------------------
// Fires a same-origin, cache-busted image request for every click on an
// interactive element, labeled with its visible text. It'll usually
// 404 against the API/webui router -- that's fine, Caddy still logs
// the request line before it reaches the backend. Read with:
//   jq -r 'select(.request.uri | startswith("/__sandbox_click")) | .request.uri' \
//     /var/log/caddy/access.log | sed 's/.*label=//;s/&.*//' | sort | uniq -c | sort -rn
(function () {
  document.addEventListener("click", function (e) {
    var el = e.target.closest("button, a, [role='tab'], [data-nav]");
    if (!el) return;
    var label = (el.textContent || "").trim().slice(0, 60);
    if (!label) return;
    var beacon = new Image();
    beacon.src = "/__sandbox_click?label=" + encodeURIComponent(label) +
      "&path=" + encodeURIComponent(location.hash || location.pathname) +
      "&t=" + Date.now();
  }, true);
})();

// ---- 4. Feedback widget (rides on the same log-beacon pattern) --------
// Floating button -> 4-option rating + optional comment -> fired as a
// GET beacon (same trick as click tracking, section 3 above) so Caddy's
// access log captures it with no new backend endpoint needed. Read
// with:
//   jq -r 'select(.request.uri | startswith("/__sandbox_feedback")) | .request.uri' \
//     /var/log/caddy/access.log
(function () {
  var RATINGS = ["Poor", "Fair", "Good", "Excellent"];

  var btn = document.createElement("button");
  btn.id = "tt-feedback-btn";
  btn.type = "button";
  btn.textContent = "Feedback";
  btn.setAttribute("aria-expanded", "false");
  btn.setAttribute("aria-controls", "tt-feedback-panel");
  document.body.appendChild(btn);

  var panel = document.createElement("div");
  panel.id = "tt-feedback-panel";
  panel.setAttribute("role", "region");
  panel.setAttribute("aria-labelledby", "tt-fb-header-id");
  panel.hidden = true;
  panel.innerHTML =
    '<div class="tt-fb-header" id="tt-fb-header-id">Rate this page</div>' +
    '<div class="tt-fb-ratings">' +
    RATINGS.map(function (r) {
      return '<button type="button" class="tt-fb-rating" data-rating="' + r + '">' + r + "</button>";
    }).join("") +
    "</div>" +
    '<textarea class="tt-fb-comment" maxlength="500" placeholder="Anything specific? (optional)" aria-label="Additional feedback"></textarea>' +
    '<div class="tt-fb-actions">' +
    '<button type="button" class="tt-fb-cancel">Cancel</button>' +
    '<button type="button" class="tt-fb-submit" disabled>Send</button>' +
    "</div>" +
    '<div class="tt-fb-thanks" hidden>Thanks &mdash; sent.</div>';
  document.body.appendChild(panel);

  var selectedRating = null;
  var ratingButtons = panel.querySelectorAll(".tt-fb-rating");
  var submitBtn = panel.querySelector(".tt-fb-submit");
  var cancelBtn = panel.querySelector(".tt-fb-cancel");
  var commentBox = panel.querySelector(".tt-fb-comment");
  var thanks = panel.querySelector(".tt-fb-thanks");

  function currentPageLabel() {
    var active = document.querySelector("[aria-current=page]");
    if (active && active.textContent.trim()) {
      return active.textContent.trim().slice(0, 60);
    }
    var h = document.querySelector("h1, h2, [role='heading']");
    var label = (h && h.textContent || document.title || "").trim().slice(0, 60);
    return label || (location.hash || location.pathname);
  }

  ratingButtons.forEach(function (rb) {
    rb.addEventListener("click", function () {
      selectedRating = rb.getAttribute("data-rating");
      ratingButtons.forEach(function (x) { x.classList.remove("tt-fb-selected"); });
      rb.classList.add("tt-fb-selected");
      submitBtn.disabled = false;
    });
  });

  function closeFeedbackPanel(focusButton) {
    panel.hidden = true;
    btn.setAttribute("aria-expanded", "false");
    if (focusButton) btn.focus();
  }

  function openFeedbackPanel() {
    panel.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    thanks.hidden = true;
    selectedRating = null;
    commentBox.value = "";
    ratingButtons.forEach(function (x) { x.classList.remove("tt-fb-selected"); });
    submitBtn.disabled = true;
  }

  btn.addEventListener("click", function () {
    if (panel.hidden) openFeedbackPanel(); else closeFeedbackPanel(false);
  });

  panel.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { e.preventDefault(); closeFeedbackPanel(true); }
  });

  cancelBtn.addEventListener("click", function () {
    closeFeedbackPanel(true);
  });

  submitBtn.addEventListener("click", function () {
    if (!selectedRating) return;
    var beacon = new Image();
    beacon.src = "/__sandbox_feedback?page=" + encodeURIComponent(currentPageLabel()) +
      "&rating=" + encodeURIComponent(selectedRating) +
      "&comment=" + encodeURIComponent(commentBox.value.trim().slice(0, 500)) +
      "&t=" + Date.now();
    panel.querySelector(".tt-fb-header").hidden = true;
    panel.querySelector(".tt-fb-ratings").hidden = true;
    commentBox.hidden = true;
    panel.querySelector(".tt-fb-actions").hidden = true;
    thanks.hidden = false;
    setTimeout(function () {
      closeFeedbackPanel(false);
      panel.querySelector(".tt-fb-header").hidden = false;
      panel.querySelector(".tt-fb-ratings").hidden = false;
      commentBox.hidden = false;
      panel.querySelector(".tt-fb-actions").hidden = false;
    }, 1500);
  });
})();

// ---- 5. Simulated live telemetry badge (sandbox flavor only) ----------
// Numbers here are hardcoded/simulated for the demo, not measured from a
// real scan -- this exists purely to signal "this thing is fast and
// local-first" the way a live badge would, without wiring up real timing
// instrumentation just for the sandbox.
(function () {
  var SAMPLES = [
    "Discovery scan completed in 4.2s across 3 subnets",
    "Evidence collection: 118 hosts refreshed in 6.8s",
    "0% cloud data leakage — 100% local execution",
    "Policy evaluation: 42 rules checked in 0.9s",
    "Agent check-in latency: 210ms median"
  ];
  var badge = document.createElement("div");
  badge.id = "tt-telemetry-badge";
  badge.setAttribute("role", "status");
  badge.setAttribute("aria-label", "Simulated performance metrics for this demo");
  var dot = document.createElement("span");
  dot.className = "tt-telemetry-dot";
  dot.setAttribute("aria-hidden", "true");
  var text = document.createElement("span");
  document.body.appendChild(badge);
  badge.appendChild(dot);
  badge.appendChild(text);

  var i = 0;
  function show() {
    text.textContent = SAMPLES[i % SAMPLES.length];
    i++;
  }
  show();
  setInterval(show, 6000);
})();
