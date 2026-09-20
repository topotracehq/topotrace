# Compliance & software lists

## Software allow/deny lists

A `SoftwareRule` matches installed-software package names
(case-insensitive, optional trailing `*` wildcard), scoped to a board
group or every host. **Deny** rules always apply -- any match is a
violation. **Allow** rules only start enforcing once at least one
exists for a scope: an empty allowlist means "no opinion yet," not
"everything is unauthorized," the same absence-is-unknown-not-bad
principle posture scoring already uses.

Manage them under `GET/POST /api/software-rules` (`admin` to write),
or from the dashboard's **Compliance** tab. Violations show up at
`GET /api/hosts/{host}/software-violations`, and the background
evaluator records an audit entry plus fires a `software_violation`
webhook the moment one appears -- the same trail policy-rule
violations already leave.

## Shadow AI detection

Alongside operator-defined software rules, TopoTrace ships a built-in,
pre-seeded ruleset (`internal/allowlist.ShadowAIPatterns`) flagging
known AI desktop apps, CLI tools, and browser extensions
found in a host's `installed_software` fact. No setup
required: every deployment can answer "do we have unauthorized AI
tooling anywhere" on day one, the same "invisible SaaS/tool sprawl"
problem enterprise browser security products build shadow-IT/shadow-AI
detection around.

An AI tool an operator has explicitly sanctioned via a `Kind: "allow"`
software rule matching its name is excluded -- approved software isn't
shadow IT. That check is independent of the generic allow/deny
enforcement above: sanctioning one AI tool for a group never turns on
full allowlist enforcement (flagging every *other* package in that
scope) as a side effect.

Shadow AI detections show up as their own labeled `shadow_ai` field at
`GET /api/hosts/{host}/software-violations` (next to, never mixed
into, the generic `violations` list), as their own card on a host's
detail page, as a `hosts_with_shadow_ai`/`total_shadow_ai_findings`
pair on `GET /api/summary` and the Fleet tab, and as their own TopoTrace
Baseline compliance check (`no-shadow-ai`).

## Browser extension inventory

The Linux, macOS and Windows agents now enumerate every installed
extension in every Chromium-family browser profile on the host (Chrome,
Chromium, Brave, Edge -- each keeps `<profile>/Extensions/<id>/<version>/manifest.json`)
and ship the raw `manifest.json` (plus the English `messages.json`, for
localized names) base64-encoded in one `browser_extensions.txt` capture
file. The server parses the manifests as real JSON
(`internal/cook.parseBrowserExtensions`) into a `browser_extensions`
fact: browser, user/profile, id, name, version, manifest version,
permissions, host permissions, and whether it came from an official web
store.

`internal/browserext` then scores each one, riskiest first, with the
reasons stated: broad host access (`<all_urls>` and friends), sensitive
permissions (request interception, cookies, native messaging, clipboard,
debugger, proxy, history, ...), broad access *combined with*
request/cookie/script access, sideloading, a deprecated manifest v2,
and a small curated deny-list. A small curated trusted list (ad
blockers, password managers, Google Docs Offline) keeps extensions
whose broad permissions are the whole point from drowning out a
sideloaded wallet helper on the same host. Both lists are illustrative
and small, like the vulnerability dataset; the real version is an
operator-maintained sanctioned-extensions list synced from a feed.

Findings surface at `GET /api/hosts/{host}/browser-extensions`, as a
card on the host page, as `hosts_with_risky_extensions` /
`total_risky_extensions` on `GET /api/summary` and a Fleet tile, as a
factor in the blended risk score, and as the TopoTrace Baseline check
`no-risky-browser-extensions`.

## Compliance frameworks

A `compliance.Framework` is a small, fixed set of named checks scored
as a percentage. **TopoTrace Baseline**, the one built in today, checks:
reporting recently (not stale), a posture score of at least 70, no
known-vulnerable packages, no denied/unauthorized software, a
vendor-supported OS (`internal/eol`), no expired or expiring server
certificates (`internal/certs`), no risky browser extensions (see
above), and no unauthorized AI tools detected (shadow AI, see above).

This is explicitly **not** a certified mapping to CIS Benchmarks,
SOC 2, PCI DSS, or any other real standard -- it's built entirely from
signals TopoTrace already computes for real, the same "small, honest
illustration" spirit as the static vulnerability dataset. Treat it as
the foundation a real control mapping could sit on, not a substitute
for one.

Two more frameworks ship alongside Baseline to prove the abstraction is
pluggable rather than a single hardcoded checklist (`internal/
compliance/frameworks.go`):

- **HIPAA Security Rule (illustrative)** -- six checks named after the
  safeguards they draw evidence from: 164.308(a)(1)(ii)(A) risk
  analysis (not stale), 164.308(a)(5)(ii)(B) protection from malicious
  software (no known vulns, no denied software), 164.308(a)(5)(ii)(A)
  patching (no pending updates), 164.312(a)(1) access control (firewall
  active), 164.312(b) audit controls (inventory present), 164.312(e)(1)
  transmission security at the browser layer (no risky extensions, no
  unsanctioned AI tools).
- **NIST SP 800-53 (illustrative subset)** -- CM-8 system component
  inventory, SI-2 flaw remediation, CM-7 least functionality, SC-7
  boundary protection, CM-11 user-installed software, RA-5
  vulnerability monitoring.

Same caveat, stated again because the names carry weight: these map
the handful of controls a fleet-inventory tool can actually observe
evidence for, each check names the control it draws on so the stretch
is visible, and none of it is a certified or complete mapping.

`GET /api/hosts/{host}/compliance` evaluates every framework for one
host; `GET /api/compliance/summary?framework=<id>` rolls one up
fleet-wide (default `baseline`), including how many hosts fail each
check; `GET /api/compliance/frameworks` lists them. The Compliance tab
has a framework selector, and each host page shows all three side by
side. Score history and time-to-remediate stay on Baseline.

`GET /api/hosts/{host}/compliance` evaluates every framework for one
host; `GET /api/compliance/summary` rolls Baseline up fleet-wide
(average score, how many hosts pass every check outright).
