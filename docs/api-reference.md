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
- `GET /api/hosts/{host}/compliance` -- every built-in compliance
  framework's score for this host.
- `GET /api/compliance/summary` -- fleet-wide compliance rollup.
- `GET/POST /api/software-rules`, `DELETE /api/software-rules/{id}` --
  manage allow/deny software rules. Write requires `admin`.

## Policies & remediation

- `GET/POST /api/policies`, `DELETE /api/policies/{id}` -- background
  evaluator rules (`admin` to write).
- `POST /api/hosts/{host}/actions` -- queue a remediation action
  (`remediate` or higher).
- `GET /api/hosts/{host}/actions` -- action history.

## Enrollment & agent downloads

- `GET/POST /api/enrollments`, `DELETE /api/enrollments/{id}` --
  manage per-host enrollment tokens (`admin`).
- `GET /api/agents/download/{platform}` -- unauthenticated script
  download (`linux`, `macos`, `windows`).
- `POST /api/mobile-report` -- JSON fact report (Android/iOS), an
  enrollment token as bearer auth.
- `POST /api/cloud-report` -- JSON fact report (batch) from a cloud
  scanner (AWS/Azure/GCP); requires the server's master token, not
  a per-host enrollment (one scan legitimately covers many instances).
- `POST /api/airgap-report` -- decode-and-cook a base64 air-gapped
  report, an enrollment token as bearer auth.
- `POST /api/discover-report` -- ingest a network-discovery sweep's
  results as `DiscoveredAsset` records.

## Ask Muster

- `POST /api/ask` -- `{"question": "..."}`, `readonly` or higher.
  Answers a natural-language question about the fleet using the
  Anthropic Messages API, grounded in a compact JSON snapshot built
  from the Store (never a live model call with no context). Returns
  `503` with a clear message if `-ai-api-key`/`MUSTER_AI_API_KEY` isn't
  set. Every question and answer (truncated) is recorded to the audit
  log as an `ask-muster` entry. See the Ask Muster doc page.

## Fleet, audit, keys, auth

- `GET /api/summary` -- fleet rollup (counts, average posture, hosts
  with shadow AI detections, etc).
- `GET /api/audit` -- audit trail (`admin`).
- `GET/POST /api/keys`, `DELETE /api/keys/{id}` -- named API keys
  (`admin`).
- `GET /api/auth/login`, `GET /api/auth/callback`, `POST /api/auth/logout`
  -- OAuth2/OIDC login for the web dashboard, if configured. See the
  Security Model page.

## Everything else

- `GET /healthz` -- liveness.
- `GET /metrics` -- Prometheus text format.
- `GET /#/...` -- the web dashboard itself (Hosts, Board, Fleet,
  Compliance, Ask Muster, Agents, Docs).
