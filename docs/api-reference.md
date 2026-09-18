# API reference

Every endpoint below is JSON in, JSON out. Authentication is a bearer
token (`Authorization: Bearer <token>`) once `-auth-token` is set; see
the Security Model page. Endpoints are grouped by what they're about,
not alphabetically.

## Hosts & facts

- `GET /api/hosts` -- list all hosts, with optional `?stale=true` and
  query-string field filters.
- `GET /api/hosts/{host}` -- one host plus every fact category it's
  reported.
- `GET /api/hosts/{host}/facts/{category}` -- one fact category.
- `GET /api/hosts/{host}/changes` -- recorded field-level diffs.
- `PATCH /api/hosts/{host}` -- set board group/tags. Requires
  `remediate` or higher.
- `GET /api/query?category=&field=&contains=` -- search across hosts.

## Posture, vulnerabilities, compliance, software lists

- `GET /api/hosts/{host}/posture` -- on-demand 0-100 score.
- `GET /api/hosts/{host}/vulnerabilities` -- known-vulnerable installed
  packages (static dataset + live OSV.dev feed if `-vuln-feed` is on).
- `GET /api/hosts/{host}/software-violations` -- denied/unauthorized
  installed software (`violations`), plus shadow AI detections
  (`shadow_ai`) against the built-in `internal/allowlist.ShadowAIPatterns`
  ruleset, per the software rules in scope for this host.
- `GET /api/hosts/{host}/browser-extensions` -- every extension the
  host's agent found in its Chromium-family browser profiles, scored
  by `internal/browserext` (riskiest first, with reasons), plus
  `reported` (false when the agent never sent the category), `total`
  and `risky` counts.
- `GET /api/hosts/{host}/sbom` -- the host's installed software as a
  CycloneDX 1.5 JSON bill of materials (`application/vnd.cyclonedx+json`,
  served as a download): one component per package with a purl
  (`pkg:deb/ubuntu/...` on Linux, `pkg:generic/...` elsewhere), plus
  the host's known vulnerability findings in CycloneDX's own
  `vulnerabilities` section. OS-package level, not an application
  dependency SBOM.
- `GET /api/hosts/{host}/lifecycle` -- the host's OS end-of-support
  status (`eol` / `ending-soon` / `supported` / `unknown`, with the
  vendor date; macOS dates are estimates and say so) and every server
  certificate the agent found with its expiry verdict (`expired` /
  `expiring` within 30 days / `ok`).
- `GET /api/software/sprawl` -- the fleet's installed software rolled
  up against `internal/sprawl`'s illustrative commercial/SaaS catalog:
  seats per product, licensed seats, hosts covered, and categories
  where more than one product does the same job.
- `GET /api/hosts/{host}/baseline` -- the host's golden baseline (if
  any) compared against its facts right now: `has_baseline`, when and
  by whom it was captured, and a `drift` list (category, field,
  add/remove/update, old/new) with per-category counts. List-shaped
  categories are diffed item by item (e.g. "vsftpd added"), not as one
  stringified array.
- `POST /api/hosts/{host}/baseline` -- capture the host's current facts
  as its baseline, replacing any existing one. Body `{"note": "...",
  "categories": [...]}`, both optional. `admin`, strictly checked;
  audited as `baseline-captured`.
- `DELETE /api/hosts/{host}/baseline` -- clear it. `admin`, strict.
- `GET /api/drift` -- every baselined host's drift report, drifted
  hosts first, with `baselined`/`drifted` counts.
- `GET /api/hosts/{host}/risk` -- the host's blended 0-100 risk score
  (higher is riskier) with the factor breakdown that produced it:
  vulnerability severity, posture deficit, staleness, Shadow AI and
  software-policy violations, multiplied by the host's
  `criticality:<low|medium|high|critical>` and `exposure:internet`
  tags. See `internal/risk`.
- `GET /api/risk` -- every host's risk score, riskiest first, plus the
  count per level and the fleet average.
- `GET /api/benchmark` -- the fleet's headline numbers (average
  posture/compliance, % hosts with vulnerabilities / stale / with
  Shadow AI, mean time to remediate when measurable) against
  `internal/benchmark`'s reference baseline, with a better/worse verdict
  per metric. The baseline is illustrative, hand-authored reference
  data, and the response's `baseline` field says so.
- `GET /api/hosts/{host}/compliance` -- every built-in compliance
  framework's score for this host.
- `GET /api/compliance/summary?framework=<id>` -- fleet-wide compliance
  rollup for one framework (default `baseline`; also `hipaa`,
  `nist-800-53`): average score, fully-compliant count, per-host
  scores, and how many hosts fail each check.
- `GET /api/compliance/frameworks` -- the built-in frameworks (id,
  name, description, check count).
- `GET/POST /api/software-rules`, `DELETE /api/software-rules/{id}` --
  manage allow/deny software rules. Write requires `admin`.

## Policies & remediation

- `GET /api/alerts` -- the deduplicated set of currently open
  policy/software violations the evaluator tracks between runs: key,
  rule, host, reason, first/last seen, occurrence count, snooze state.
- `POST /api/alerts/snooze` -- `{"key": "...", "hours": N}` quiets one
  open violation's re-announcements for N hours (0 clears). `remediate`,
  strict, audited as `alert-snoozed`.
- `GET /api/approvals` -- auto-remediations parked by rules with
  `require_approval`, oldest first.
- `POST /api/approvals/{id}/approve` / `.../reject` -- queue the
  proposed action (through `remediate.Validate`) or drop it.
  `remediate`, strict, audited as `remediation-approved` /
  `remediation-rejected`.
- `GET/POST /api/policies`, `DELETE /api/policies/{id}` -- background
  evaluator rules (`admin` to write). A rule with `auto_remediate` may
  also set `require_approval: true` to park each proposed action in
  the approvals queue instead of queuing it.
- `POST /api/hosts/{host}/actions` -- queue a remediation action
  (`remediate` or higher).
- `GET /api/hosts/{host}/actions` -- action history.

## Enrollment & agent downloads

- `GET/POST /api/enrollments`, `DELETE /api/enrollments/{id}` --
  manage per-host enrollment tokens (`admin`).
- `GET /api/agents/download/{platform}` -- unauthenticated script
  download (`linux`, `macos`, `windows`).
- `POST /api/mobile-report` -- JSON fact report (Android/iOS/ChromeOS),
  an enrollment token as bearer auth.
- `POST /api/cloud-report` -- JSON fact report (batch) from a cloud
  scanner (AWS/Azure/GCP); requires the server's master token, not
  a per-host enrollment (one scan legitimately covers many instances).
- `POST /api/airgap-report` -- decode-and-cook a base64 air-gapped
  report, an enrollment token as bearer auth.
- `POST /api/discover-report` -- ingest a network-discovery sweep's
  results as `DiscoveredAsset` records.

## Ask Muster

- `POST /api/ask` -- `{"question": "..."}`, `readonly` or higher.
- `POST /api/ask/draft-policy` -- `{"description": "..."}` in plain
  English; out, a `draft` in `POST /api/policies`'s own field names
  (name, kind, threshold, category, group, auto_remediate,
  auto_remediate_arg, require_approval) plus an `explanation` and a
  `source` (`ask-muster`, or `heuristic` when no API key is configured
  and keyword rules drafted it instead). Nothing is created -- the
  operator reviews and posts it. `readonly`; audited as `ask-muster`.
- `POST /api/ask/summary` -- a four-paragraph plain-English executive
  summary of the fleet from the same data as the executive report,
  written by Ask Muster or (no key) filled from a template; `source`
  says which. `readonly`; audited.
  Answers a natural-language question about the fleet using the
  Anthropic Messages API, grounded in a compact JSON snapshot built
  from the Store (never a live model call with no context). Returns
  `503` with a clear message if `-ai-api-key`/`MUSTER_AI_API_KEY` isn't
  set. Every question and answer (truncated) is recorded to the audit
  log as an `ask-muster` entry. See the Ask Muster doc page.

## Fleet, audit, keys, auth

- `GET /api/summary` -- fleet rollup (counts, average posture, hosts
  with shadow AI detections, etc).
- `GET /api/history?days=N` -- fleet-wide score trend (default 30
  days, max 365): one bucket per day (per hour when `days<=2`) with
  average posture, average compliance, hosts with vulnerabilities and
  stale hosts, plus a `mttr` rollup -- mean/median time to remediate
  over spans that closed in the window, how many hosts are still
  non-compliant, and the oldest open span. Built from the per-host
  series the background evaluator records once per run (see the
  Fleet dashboard page); empty buckets on a brand-new server.
- `GET /api/hosts/{host}/history?days=N` -- one host's raw recorded
  points (posture, compliance, vulnerability count, stale) inside the
  window, oldest first.
- `GET /api/audit` -- audit trail (`admin`).
- `GET/POST /api/keys`, `DELETE /api/keys/{id}` -- named API keys
  (`admin`).
- `GET /api/auth/login`, `GET /api/auth/callback`, `POST /api/auth/logout`
  -- OAuth2/OIDC login for the web dashboard, if configured. See the
  Security Model page.
- `GET /api/graph` -- the network/asset relationship picture, laid
  out server-side (`internal/graph`): hub nodes per /24 subnet (from
  `network_interfaces` facts and discovery CIDRs) or per board group,
  managed hosts with their risk level, discovered assets, and
  `same-host` edges where a discovered address matched an enrolled
  host.
- `GET/POST /api/bookmarks`, `GET /api/bookmarks/{id}/diff`,
  `DELETE /api/bookmarks/{id}` -- "since last time": snapshot the
  fleet's headline state (every host's posture/compliance/risk/vulns/
  stale/group, rule and asset counts) under a name, then diff it
  against the live fleet: hosts added/removed, scores up or down,
  findings new or fixed, each marked better/worse. Create/delete are
  `remediate`, strict, audited.
- `GET /api/demo/scenarios`, `POST /api/demo/simulate` -- the
  simulator: fire a synthetic policy violation, software violation,
  proposed remediation, resolution, operator burst or admin-key
  creation (or the whole story) through the real audit trail (and so
  SIEM forwarding), the real notification queue and the behavioral
  signals. Entries are marked `(simulated)`. `admin`, strict, audited.
- `GET /api/trust/{host}?min=N` -- the device-trust verdict for an
  external access gate (`readonly`, so a gate can hold a key scoped to
  nothing else): `score` (100 minus the blended risk score), `level`
  (`trusted` >= 75, `conditional` >= 50, else `untrusted`; a stale host
  is never `trusted`), `allow` (score >= `min`, default 50), the
  reasons, and the thresholds. An unenrolled host gets an `untrusted`
  verdict rather than a 404. Denied decisions are audited as
  `trust-denied`. See the README's zero-trust section for an
  `auth_request` example.
- `GET /api/signals?days=N` -- `internal/ueba`'s behavioral findings
  over the audit trail (`admin`): off-hours writes, bursts, mass
  deletes, remediation runs, new admin keys, settings changes,
  first-seen actors -- each with the rule, actor, count and audit IDs.
- `GET /api/breaches?domain=example.com` -- Have I Been Pwned lookup
  (`admin`, audited): with `-hibp-api-key`, every alias on the domain
  found in a breach; always, the public list of breaches of the domain
  itself, and a `mode` string saying which you got.
- `GET /api/notifications/queue` -- the outbound delivery queue
  (`admin`): configured sinks (generic webhook URLs redacted to their
  host), pending deliveries with attempts/next attempt/last error, and
  dead letters. See the README's Notifications section.
- `POST /api/notifications/test` -- deliver one synthetic event
  (default type `test`; body `{"type","host","detail"}` optional) to
  every sink synchronously and report each sink's outcome. `admin`,
  strict, audited as `notification-test`.
- `GET /api/settings` -- server-level configuration snapshot (`admin`):
  storage backend, listen addresses, evaluator interval, and whether
  auth/OAuth/the vuln feed/Ask Muster/webhooks/SIEM forwarding are
  configured, with non-secret metadata (mode, counts, intervals, model
  name, OAuth role-map) for each -- never a token, DSN, API key, or
  webhook/OAuth URL itself.
- `PATCH /api/settings` -- live-reconfigure SIEM forwarding and/or Ask
  Muster (`admin`, always checked strictly -- this endpoint refuses to
  run with no `-auth-token` set, unlike the `GET`). Takes effect
  immediately, no restart: SIEM forwarding is backed by a
  `siemforward.Dynamic` and Ask Muster by an `aiquery.ConfigStore`,
  both swappable at runtime. Also persisted to
  `<data-dir>/settings-overrides.json` (0600) so the change survives a
  restart, unless the process was started with a `-siem-hec-*` /
  `-ai-api-key` flag or env var already set, which always takes
  precedence over a saved override. Body fields (all optional, but at
  least one required):
  - `siem_hec_url`, `siem_hec_token` -- must be provided together to
    configure or change Splunk HEC forwarding (the current URL/token
    are never readable back, so changing either means resending both).
  - `siem_disable` -- `true` turns SIEM forwarding off.
  - `ai_api_key` -- sets/changes the Anthropic API key. Omit to keep
    the current key while changing only `ai_model`.
  - `ai_model` -- sets/changes the model id. Sending `""` resets to
    the built-in default.
  - `ai_disable` -- `true` turns Ask Muster off.

  Returns the same shape as `GET /api/settings`, reflecting the change.
  Every accepted edit is written to the audit trail (`settings_updated`),
  detail text only, never a secret value.

## Reports & exports

- `GET /api/reports/executive` -- a standalone, print-ready HTML
  executive summary (fleet stats, 30-day trend, highest-risk hosts,
  known vulnerabilities, and -- for an admin credential -- recent
  audit activity). Use the browser's Print / Save as PDF; there is
  deliberately no PDF library. `readonly`.
- `GET /api/reports/{compliance|risk|vulnerabilities|audit}.csv` --
  CSV exports built from the same signals the dashboard shows,
  served with a `Content-Disposition: attachment` filename. `audit` is
  `admin`; the rest are `readonly`.

## Everything else

- `GET /healthz` -- liveness.
- `GET /metrics` -- Prometheus text format.
- `GET /#/...` -- the web dashboard itself (Hosts, Board, Fleet,
  Compliance, Ask Muster, Agents, Docs).
