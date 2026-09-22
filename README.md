# TopoTrace

**Turn Infrastructure Into Insight**

![TopoTrace](internal/webui/static/img/topotrace-lockup-light.svg)

Formerly Muster. See the [brand guide](docs/brand-guide.md) for assets and compatibility details.

A hardware/software/configuration inventory system: lightweight agents
report data from managed hosts, a Go server ingests and parses it, and a
REST API answers questions like "which of my servers are running Ubuntu?"

The [fleet workspace](docs/fleet-workspace.md) adds an actionable home page,
global evidence search, saved device collections, comparison, an attention
inbox, integration health, guided onboarding, and branded report selection.
[Site workers](docs/site-operations.md) support bounded scheduled discovery
and explicitly staged Linux SSH / Windows WinRM agent deployment.

This is a **from-scratch project**, written in Go, inspired by — but not
ported from — an older Perl system I modernized separately. The domain
(agents → central collector → parsed/"cooked" facts → queryable reports)
is the same well-worn shape a lot of inventory/config-management tooling
uses; the design and code here are new.

## Why this exists

TopoTrace started as a from-scratch systems project: a concurrent TCP
network service, a text-parsing pipeline, a clean storage abstraction,
and a REST API. It's now the foundation of TopoTrace LLC's Community
edition, built for teams who want self-hosted fleet inventory and
compliance posture tooling they can run and audit themselves.

## Architecture

```
   agent  --TCP (TOPOTRACE1 protocol)-->  ingest daemon  --tar.gz extract-->  raw/<platform>/<host>/<snapshot>/*.txt
                                              |
                                              v
                                        cook pipeline (per-platform parser)
                                              |
                                              v
                                         Store interface
                                    (memstore: in-memory + JSON
                                     snapshot, zero setup --or--
                                     pgstore: real Postgres, same
                                        interface, pick with a flag)
                                              |
                                              v
                                        HTTP REST API  <-- also serves the web dashboard
```

Open `http://localhost:8080/` for the dashboard, or hit `/api/*` directly.

- **`internal/ingest`** — the TCP daemon. One goroutine per connection.
  A tiny hand-rolled framed protocol (`TOPOTRACE1 <platform> <host>
  <bytes>\n` + that many bytes of gzip'd tar), documented in
  `protocol.go`. Guards against zip-slip on extraction and caps payload
  size, since this is untrusted network input landing on disk before any
  auth layer exists (that gap is called out explicitly in
  `ingest/server.go` — v1 has no per-agent auth yet).
- **`internal/cook`** — turns a raw snapshot directory into structured
  facts. One file per platform (`linux.go` and `windows.go`);
  `pipeline.go` finds the newest snapshot for a host and dispatches to
  the right parser. Windows deliberately reuses Linux's field names
  (`os`, `cpu_model`, `memory_mb`, ...) wherever the concepts map
  reasonably, so the web UI needs zero per-platform code to display
  either one.
- **`internal/store`** — the persistence contract (`Store` interface) and
  the field-level diff logic (`Diff`) shared by every implementation, so
  "what changed since last cook" means the same thing no matter which
  backend is storing the result.
  - **`memstore`** — in-memory, mutex-guarded, snapshotted to a JSON file
    on every write so state survives a restart. Zero setup: this is the
    default, and it's all `go run ./cmd/topotrace` needs.
  - **`pgstore`** — a real Postgres backend. Facts are stored as JSONB
    (categories have different shapes; the store layer treats a fact's
    data as an opaque document, not a fixed schema), `UpsertFact` diffs
    and records changes inside one transaction with the previous row
    locked `FOR UPDATE` so two concurrent reports for the same
    host/category can't race, and `Query`'s substring match is a
    parameterized, LIKE-metacharacter-escaped `ILIKE` so it behaves the
    same as memstore's `strings.Contains`, not a glob. Schema is applied
    by a real migration runner (`pgstore/migrate.go`): every file in
    `pgstore/migrations/` (`0001_init.sql`, `0002_actions.sql`,
    `0003_groups.sql`, ...) that isn't yet recorded in a
    `schema_migrations` table gets applied, in order, on every startup --
    including a first run against a database built by an older topotrace
    before this migration runner existed, which just backfills
    `schema_migrations` without changing anything (every statement is
    still `CREATE ... IF NOT EXISTS`).

  Nothing above this layer (`cook`, `api`) knows or cares which one is
  backing it -- that's the point of the interface. Pick with a flag, see
  "Running it" below.
- **`internal/api`** — REST API (stdlib `net/http`, Go 1.22+ pattern
  routing, no router dependency) over whatever the store holds. Beyond
  read endpoints, `PATCH /api/hosts/{host}` is the one board write in
  the API surface: `{"group": "..."}` and/or `{"tags": [...]}` assign a
  host to a board column and/or freeform labels (see
  `Store.SetHostGroup`/`SetHostTags` -- deliberately separate from the
  cook pipeline's `UpsertHost`, so a re-cook can never clobber them).
  `GET /api/hosts/{host}/changes[?limit=N]` surfaces the change-tracking
  data every `UpsertFact` already records, newest first. Also owns the
  RBAC gate (`requireRole`/`requireRoleStrict`) every other package's
  endpoints sit behind -- see "Authentication, roles & remediation".
- **`internal/policy`** — `IsStale` (the 24h staleness rule) plus
  `ComputePosture`, a small, fixed heuristic scoring a host 0-100 from
  whatever facts are on hand (see "Compliance posture scoring"). Both
  are computed on demand, never stored, so the API, the evaluator, and
  the web UI's `STALE` badge all agree by construction.
- **`internal/vuln`** — a small curated dataset of real CVEs
  (`data.go`) plus `Check`, which cross-references an
  `installed_software` fact against it (see "Vulnerability correlation").
  Explicitly not a live feed -- see that section for exactly what's out
  of scope.
- **`internal/evaluator`** — the background loop tying policy rules,
  posture, vulnerability correlation, auto-remediation, the audit trail,
  and webhooks together: on a fixed interval, evaluate every host
  against every persisted `model.Rule`, and act on any violation (see
  "Policy rules & the background evaluator"). The unattended
  counterpart to `internal/api`'s human/scripted remediation path --
  both go through the same `internal/remediate.Validate` allow-list.
- **`internal/webhook`** — a minimal outbound event notifier: one
  attempt, one retry, POSTed as JSON to every configured URL, nil-safe
  so callers never branch on whether webhooks are even configured (see
  "Webhooks").
- **`internal/webui`** — the web dashboard: a dependency-free single-page
  app (plain HTML/CSS/JS, no build step, no framework) embedded into the
  binary via `embed.FS` and served from the same port as the API.
  Branded with the real TopoTrace logo/icon assets (cropped and
  color-matched from source artwork, see `static/img/`). Three views:
  - **Hosts** (`#/`) — the grid, with per-platform icons, a host detail
    page, and a search bar over `/api/query`.
  - **Board** (`#/board`) — a Trello-style Kanban view: one column per
    `Host.Group` (plus an always-present "Ungrouped"), native HTML5
    drag-and-drop to move a card between columns (`PATCH`es the group),
    and a text field to start a new, empty column. Cards show tag
    labels and a `STALE` badge for anything that hasn't reported in
    over 24h (a display heuristic client-side, backed server-side too --
    see `internal/policy.IsStale`). The host detail page has editors for
    group and tags (add/remove, autosaves via the same PATCH endpoint),
    a compliance-posture card and a vulnerabilities card (reading the
    new `/posture` and `/vulnerabilities` endpoints), and a "Recent
    changes" timeline reading `/api/hosts/{host}/changes`.
  - **Fleet** (`#/fleet`) — the aggregate view: stat tiles from
    `/api/summary` (total/stale hosts, average posture, hosts with
    vulnerabilities), a by-platform breakdown, the configured policy
    list, and -- for a credential with the `admin` role -- the most
    recent audit entries (quietly omitted, not an error, for anything
    less than `admin`).
- **`cmd/topotrace`** — the server binary: runs the ingest daemon, the API,
  and the web UI together, one process, shared store.
- **`cmd/demoagent`** — *not* a real agent. A minimal test client that
  packages a directory of already-captured text files and pushes them
  over the wire, so the whole pipeline is demoable without writing a
  real per-platform collector yet.
- **`agent/windows/topotrace-agent.ps1`** — a real, if minimal, Windows
  agent: a dependency-free PowerShell script that collects CPU/memory/OS/
  hostname facts via `Get-CimInstance`, packages them with Windows' own
  built-in `tar.exe`, and sends them over the same TOPOTRACE1 protocol
  `demoagent` uses. See that file's header comment for full usage, and
  the honesty note under "Running it" below -- it's been written and
  reasoned through carefully but not run against a real Windows machine.
- **`agent/ubuntu/topotrace-agent.sh`** — the Linux counterpart: a
  dependency-free bash script that captures `/proc/cpuinfo`,
  `/proc/meminfo`, `uname -a`, `/etc/os-release`, and `uptime` (exactly
  what `internal/cook/linux.go` expects), packages them with `tar`, and
  sends them over TOPOTRACE1 using bash's built-in `/dev/tcp` -- no
  netcat/socat needed. Unlike the Windows script, this one has actually
  been run end to end against a live server (see "Running it" below).
- **`charts/topotrace/`** — a Helm chart deploying the whole stack on
  Kubernetes: the server as a Deployment, Postgres as a StatefulSet with
  a PVC, and the Ubuntu agent as a real CronJob (closing the "scheduled
  execution" gap for real) with an optional one-pod-per-node DaemonSet
  variant, plus least-privilege RBAC and a NetworkPolicy scoping who can
  reach the raw ingest port. See `charts/topotrace/README.md` for the full
  design writeup (including exactly what the RBAC/NetworkPolicy/hostPID
  choices are actually for) and its own verification-status note.

## Running it

### Locally (Go toolchain)

Requires Go 1.22+ (uses `net/http`'s method+path pattern routing).
No external services required by default, no config beyond flags —
`go run` and go. (Postgres is opt-in, see below.)

```
go run ./cmd/topotrace
```

By default this uses `memstore` (in-memory, JSON-snapshotted to
`./data/topotrace.json`). To use Postgres instead, point it at a running
Postgres with `-postgres-dsn` (or the `TOPOTRACE_POSTGRES_DSN` env var):

```
go run ./cmd/topotrace -postgres-dsn "postgres://topotrace:topotrace@localhost:5432/topotrace?sslmode=disable"
```

The schema is applied automatically on startup by the embedded migration
runner (`internal/store/pgstore/migrate.go` + `migrations/*.sql`) -- no
manual migration step, for a fresh database or an existing one.

#### A note on the Postgres driver

`go.mod` requires `github.com/lib/pq`, and its source is vendored into
`vendor/` and committed to the repo. That's a deliberate choice, not an
accident of however I happened to build this: it means `go build` (Go
1.14+ auto-detects a consistent `vendor/modules.txt` and builds with
`-mod=vendor`) never needs network access to a module proxy, on any
machine, including offline or locked-down CI. If you add or change a
dependency, the normal workflow still applies -- `go get`, `go mod
tidy`, then `go mod vendor` to refresh `vendor/`.

### In Docker

Multi-stage build (compiles with the full Go toolchain, ships a static
binary in a minimal Alpine runtime image, runs as a non-root user):

```
docker build -t topotrace .
docker run --rm -p 8080:8080 -p 9090:9090 -v topotrace-data:/app/data topotrace
```

Or with Compose, which also wires up a one-shot demo client:

```
docker compose up -d topotrace
docker compose --profile demo run --rm demoagent
```

`demoagent`'s Compose service talks to `topotrace:9090` (the Compose service
name, resolved via Docker's built-in DNS) rather than `localhost`, since
it's running as its own container on the same Compose network.

That brings up `topotrace` with the default memstore backend -- nothing
else needed. To run it against Postgres instead, bring up the `postgres`
service (behind its own profile, so it stays out of the way when you
don't want it) and point `topotrace` at it:

```
docker compose --profile postgres up -d postgres
TOPOTRACE_POSTGRES_DSN="postgres://topotrace:topotrace@postgres:5432/topotrace?sslmode=disable" \
  docker compose --profile postgres up -d topotrace
```

`postgres` here is also the Compose service name/DNS entry, same idea as
`demoagent` talking to `topotrace:9090` above. Data persists in the
`topotrace-postgres-data` named volume across restarts.

By default: ingest on `:9090`, API on `:8080`, data under `./data`. No
`-auth-token` by default either -- see "Authentication, roles &
remediation" below before pointing this at anything but localhost or a
trusted network. `-webhook-url` and `-evaluator-interval` are separate,
optional flags layered on top once you have policy rules -- see "Policy
rules & the background evaluator" and "Webhooks" below.

In another terminal, simulate an agent reporting in with the bundled
sample capture data:

```
go run ./cmd/demoagent -host demo01
```

Then either open **`http://localhost:8080/`** for the dashboard, or query
the API directly:

```
curl localhost:8080/api/hosts
curl localhost:8080/api/hosts/demo01
curl localhost:8080/api/hosts/demo01/facts/system_summary
curl "localhost:8080/api/query?category=system_summary&field=distribution&contains=Ubuntu"
```

Run it again after editing a file under `testdata/linux-demo-host/` (or
point `-dir` at a copy with a changed value) to see change-tracking:
the server log reports how many fields changed since the last report
for that host, and the `Store.UpsertFact` diff records what changed,
old value to new -- readable back via:

```
curl localhost:8080/api/hosts/demo01/changes
```

Or assign it to a board column/tags the same way the web UI's drag-drop
and tag editor do, under the hood:

```
curl -X PATCH localhost:8080/api/hosts/demo01 -d '{"group":"prod","tags":["east-dc"]}'
```

Then open `http://localhost:8080/#/board` to see it show up as a card
in the "prod" column.

### Demo seed data

`demoagent` above proves the pipeline end to end with one host; to see
the dashboard the way a populated fleet actually looks -- for a demo,
or to try out Fleet/Compliance/Ask TopoTrace with real variety on hand --
`cmd/seed` writes a realistic, varied synthetic fleet straight into the
Store: 15 hosts across Linux/Windows/macOS, a mix of compliant and
non-compliant posture, real-looking vulnerability findings against
`internal/vuln.Dataset`'s curated CVEs, three shadow AI detections plus
one generic software-allowlist violation, two hosts backdated past the
staleness threshold, a handful of policy/software rules, and a few
network-discovered-but-unmanaged assets.

```
go run ./cmd/seed              # writes into ./data/topotrace.json (memstore)
go run ./cmd/topotrace            # then (re)start the server to serve it
```

It talks to the Store directly with the same `-data-dir`/`-postgres-dsn`
flags `cmd/topotrace` itself takes -- see `cmd/seed/main.go`'s package doc
comment for exactly why (there's no "insert one host's worth of
arbitrary facts" HTTP endpoint in the API today) and for the one
honest timing caveat: against the default memstore backend this only
takes effect the next time `cmd/topotrace` (re)starts against the same
`-data-dir`, since memstore keeps its state in memory once loaded.
Point both at the same `-postgres-dsn` instead and it works against an
already-running server immediately, live, no restart needed.

### Testing with the Windows agent

To send data from an actual Windows machine instead of synthetic test
fixtures, copy `agent/windows/topotrace-agent.ps1` to it and run:

```
.\topotrace-agent.ps1 -TopoTraceHost <ip-or-hostname-of-the-topotrace-server> -TopoTracePort 9090
```

It reports as the machine's real computer name by default (`-HostName`
to override), and needs nothing beyond what Windows already ships with
(PowerShell 5.1+, `tar.exe`) -- see the script's own header comment for
the full parameter list and design notes.

**Verified against a real machine:** this script has been run for real
against a live Windows 11 machine, reporting through a live TopoTrace
server on Kubernetes -- not just proven end to end via `demoagent`
against synthetic fixtures (see `internal/cook/windows_test.go` and
`testdata/windows-demo-host/`, which is how the wire protocol and
capture-file format were originally proven before a real Windows host
was available). Real output on record: `system_summary` correctly
reported the machine's actual CPU model and Windows edition string,
and `disk_usage` correctly reported its actual C: drive capacity and
free space.

### Testing with the Ubuntu/Linux agent

Same idea for a real Linux box: copy `agent/ubuntu/topotrace-agent.sh` to
it and run:

```
./topotrace-agent.sh --topotrace-host <ip-or-hostname-of-the-topotrace-server>
```

It reports under the machine's real `hostname` by default (`--host-name`
to override), and needs nothing beyond bash, `tar`, and `gzip` -- see
the script's own header comment (or `--help`) for the full option list.

Unlike the Windows script, this one has been run for real: verified end
to end against a live TopoTrace server, collecting actual `/proc/cpuinfo`,
`/proc/meminfo`, `uname -a`, `/etc/os-release`, and `uptime` output and
confirming via the API that it parsed into accurate CPU/memory/kernel/
distribution facts.

#### Don't have a spare Ubuntu box? Use the bundled test container

`agent/ubuntu/Dockerfile` packages the script into a plain Ubuntu image
so you can run it against your `topotrace` container without needing an
actual second machine -- a genuine run of the real script (its own
container's `/proc/cpuinfo`, `uname -a`, etc.), not a canned fixture
like `demoagent`:

```
docker compose up -d topotrace
docker compose --profile ubuntu-agent run --rm ubuntu-agent
```

That builds the agent image, runs it on the same Compose network as
`topotrace` (reachable at the `topotrace` hostname, same as `demoagent`
does), reports as host `ubuntu-container01`, and exits. Check it landed:

```
curl localhost:8080/api/hosts/ubuntu-container01
```

To report under a different name or point at a different server, pass
your own arguments after `ubuntu-agent` (this replaces the default
`command` entirely, so include `--topotrace-host` too):

```
docker compose --profile ubuntu-agent run --rm ubuntu-agent \
  --topotrace-host topotrace --host-name my-test-box
```

**Unverified note:** this Dockerfile/service was written and validated
with `docker compose config` (confirms the YAML and build wiring are
correct), but not actually built or run -- there's no Docker daemon
available in the environment this was written in, only the `docker`
CLI with nothing to connect to. The script it packages has already been
proven for real (see above); what's untested here is specifically the
container build itself. Should be routine -- it's a stock Ubuntu base
image plus one `COPY`/`chmod` -- but flag if `docker compose --profile
ubuntu-agent build` hits anything unexpected.

### On Kubernetes

```
docker build -t topotrace:latest .
docker build -f agent/ubuntu/Dockerfile -t topotrace-ubuntu-agent:latest .
helm install topotrace charts/topotrace
```

Deploys the server (Postgres-backed by default, via a StatefulSet), a
CronJob running the real Ubuntu agent on a schedule, and RBAC/
NetworkPolicy scoped as described in `charts/topotrace/README.md` -- read
that file before presenting this anywhere, it explains *why* each piece
is built the way it is (why a StatefulSet at one replica, what the RBAC
actually grants and why it's off by default, what `hostPID` on the
optional DaemonSet variant is and isn't buying you), not just how to run
it. Same verification caveat as the Docker Compose section above, one
level further: no cluster or `helm`/`kubectl` binaries were available to
actually install this anywhere -- see that README's own "Verification
status" section for exactly what was and wasn't checked instead.

### Standalone (Linux VM / bare metal, systemd)

For a box that isn't Kubernetes and isn't just a local Go run either --
a home-lab server, a single small-business machine:

```
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o topotrace ./cmd/topotrace
sudo deploy/systemd/install.sh ./topotrace
```

Installs a `topotrace` system user, a systemd unit (`Restart=on-failure`,
starts on boot), and `/etc/topotrace/topotrace.env` for configuration -- same
flags as everywhere else, just env-var-driven instead of passed on a
command line. Full walkthrough, including firewall/reverse-proxy notes
and upgrading, in `deploy/systemd/README.md`.

## Authentication, roles & remediation

Every earlier round shipped with the ingest daemon flagged, in code and
in this README, as unauthenticated -- anyone who could reach the TCP
port could report data as any host. That's closed now, and the same
shared secret bootstraps a small RBAC layer plus a remediation-action
pipeline built on top of it, in the order the project settled on: auth
first, then roles, then remediation, never the other way around.

### Turning auth on

```
go run ./cmd/topotrace -auth-token "some-shared-secret"
# or: TOPOTRACE_AUTH_TOKEN=some-shared-secret go run ./cmd/topotrace
```

The token must be 1-128 characters of letters, digits, `.`, `_`, `-` --
the same charset the wire protocol already restricted platform/host
names to, so there's exactly one safe-token rule in the whole system,
not two. Leave it unset and everything behaves exactly like every
earlier round: any client can report data as any host, every `GET`
endpoint and board write stays open, and remediation, policies, and API
keys all stay unavailable -- not insecure-by-default, see below.

This `-auth-token` is the permanent **master credential** and always
resolves to the highest role, `admin` -- it's what bootstraps everything
else, including the first named API key.

### Roles

Once auth is on, every credential -- the master token or a named API
key -- carries exactly one of three fixed roles, checked with `>=` on a
small rank table, not a custom permission matrix:

| Role | Can do |
|---|---|
| `readonly` | Everything under `GET` -- hosts, facts, changes, actions, groups, posture, vulnerabilities, the fleet summary, policies. |
| `remediate` | Everything `readonly` can, plus board writes (`PATCH /api/hosts/{host}`, `POST /api/groups`) and queuing a remediation action. |
| `admin` | Everything `remediate` can, plus managing policies (`POST`/`DELETE /api/policies`), managing API keys (`POST`/`DELETE /api/keys`), and reading the audit log (`GET /api/audit`). |

**This is a deliberate behavior change from every earlier round:** the
read endpoints (`GET /api/hosts`, `/api/query`, and the rest) used to be
completely open regardless of `-auth-token`, because nothing before this
round needed more than one tier of access. Now that `readonly` exists as
a real role, leaving those endpoints ungated would make it meaningless
-- so once `-auth-token` is set, every `GET` under `/api` requires at
least a `readonly` credential too, the same as board writes always have.
`/healthz` and `/metrics` are unaffected (see "Metrics" below).

A handful of endpoints -- queuing a remediation action, managing
policies, managing API keys -- are gated with a *stricter* check that
refuses the request outright when `-auth-token` isn't set at all, rather
than falling back to demo mode's "wide open" default. Anything that can
queue an action on a host (directly, or indirectly through an
auto-remediating policy) gets this stricter gate; day-to-day reporting
data doesn't.

### Scoped API keys

`POST /api/keys` takes an optional `"group"`. A key scoped to a board
group is the "one team, one slice of the fleet" credential: host lists
and every fleet rollup (summary, risk, benchmark, reports, the network
map, bookmarks) only include that group's hosts, and any host-scoped
endpoint for a host outside the group answers 403 with a message that
says why. The master token, OAuth sessions and unscoped keys see the
whole fleet, exactly as before. Fleet-wide history and the compliance
summary are the deliberate exceptions still visible to a scoped key --
they carry no host names outside the group's own entries... except
`/api/compliance/summary`'s per-host list, which is filtered too.
Verified live: a `prod`-scoped readonly key lists five hosts, gets 403
on `WIN-HR01`, and sees `total_hosts: 5` on summary and risk.

### Managing API keys

```
# mint a readonly key for a monitoring tool
curl -X POST localhost:8080/api/keys   -H "Authorization: Bearer some-shared-secret"   -d '{"name": "datadog-poller", "role": "readonly"}'
# -> {"id":"1","name":"datadog-poller","role":"readonly","token":"<192-bit hex, shown once>", ...}

curl localhost:8080/api/keys -H "Authorization: Bearer some-shared-secret"   # list (no raw tokens -- TokenHash is never marshaled)
curl -X DELETE localhost:8080/api/keys/1 -H "Authorization: Bearer some-shared-secret"   # revoke immediately
```

The raw token is returned exactly once, in the create response -- only
its SHA-256 hash (`crypto/sha256`) is ever persisted, so losing it means
revoking that key and minting a new one, not recovering it. Generated
with `crypto/rand` (never `math/rand`), 192 bits. Every credential
comparison -- the master token and the hash lookup both -- happens
inside `requireRoleStrict`/`requireRole` using a constant-time compare
(`crypto/subtle`) for the master token, since this sits on a
network-facing path an attacker controls the timing of.

### OAuth2/OIDC dashboard login

Bearer tokens are the right fit for a script or an agent, but not for
a person clicking around the dashboard in a browser -- pasting a
192-bit key into an "Auth" box every session is exactly the friction
real single sign-on exists to remove. `-oauth-*` flags turn on a real
authorization-code login flow, alongside the token schemes above, not
instead of them:

```
go run ./cmd/topotrace -auth-token some-shared-secret   -oauth-client-id "..." -oauth-client-secret "..."   -oauth-auth-url "https://accounts.google.com/o/oauth2/v2/auth"   -oauth-token-url "https://oauth2.googleapis.com/token"   -oauth-userinfo-url "https://openidconnect.googleapis.com/v1/userinfo"   -oauth-redirect-url "http://localhost:8080/api/auth/callback"   -oauth-role-map "admin@example.com=admin,*@example.com=readonly"
```

Every `-oauth-*` flag is required together or not at all -- leave them
all empty and browser login is simply off. A person clicks **Sign in**
in the dashboard header, authenticates with the identity provider, and
comes back with a session cookie; `-oauth-role-map` maps their email
(exact address, `*@domain`, or a bare `*` catch-all, checked in that
order) onto one of the three fixed roles, exactly as if they'd used an
API key of that role. **Sign out** in the same header clears the
session immediately.

Implementation notes, so nothing here is a surprise: it's stdlib-only
Go (`internal/oauth`), same reason as the cloud agents below -- no
route to `proxy.golang.org` to vendor `golang.org/x/oauth2` in this
dev environment. It uses PKCE (RFC 7636) on top of the authorization
code, and gets the logged-in user's email from the standard OIDC
UserInfo endpoint rather than parsing/verifying an ID token's
signature -- simpler, and no JWT-verification code to get subtly
wrong. Sessions are an in-memory map, not a database table, so they
don't survive a server restart and don't work across multiple
replicas behind a load balancer -- see `internal/oauth`'s doc comment.
**This has not been tested against a live identity provider** (this
dev environment has no OAuth app registration and limited outbound
access) -- treat it as a solid first draft, and test it against your
actual IdP (Google, Okta, Azure AD, Auth0, ...) before relying on it.
See `docs/security-model.md` for the full picture alongside the other
credential tiers.

### Remediation actions

The self-healing/remediation item from every earlier "what's next" list
is real now, but deliberately small: a fixed, allow-listed set of verbs
(`internal/remediate/actions.go`) an operator can queue for a specific
host, not free-form command execution. Today the allow-list has one verb
actually wired up end to end -- `restart-service` -- and one more,
`apply-updates`, allow-listed for the shape of the feature but reporting
"unsupported" rather than silently deciding what "apply updates" should
mean on your platform. Adding a new verb is a deliberate code change in
that one file, never something the network can expand.

How an action actually reaches a host, entirely over the existing
TOPOTRACE1 connection agents already make on their normal reporting
schedule -- no new listener, no persistent agent connection, no second
channel to secure:

1. **Queue it.** `POST /api/hosts/{host}/actions` with `{"verb":
   "restart-service", "arg": "sshd"}` and a bearer token. Validated
   against the host's actual platform (from its last report) before
   anything is stored -- queuing `restart-service` for a Windows host
   with a Linux-only arg shape is rejected here, not discovered later on
   the agent.
2. **Deliver it.** The next time that host's agent reports in (on its
   normal CronJob/Scheduled Task/cron cadence -- nothing new to run),
   the server's `OK <n>` reply is followed by a second line: `ACTION
   <id> <verb> <arg>`.
3. **Execute it.** The agent script itself decides whether to act --
   only the verbs it has an explicit case branch for ever run anything.
   An unrecognized or not-yet-implemented verb is reported back as
   unsupported, never guessed at or handed to a shell as-is.
4. **Report it.** The agent opens one more short connection --
   `TOPOTRACE1-RESULT <token> <action-id> <ok|fail> <bytes>` plus a short
   plain-text detail payload -- and the result lands in that action's
   history.

`GET /api/hosts/{host}/actions` shows the queue/history for a host --
same `readonly`-gated `GET` as every other read endpoint once auth is
on, open in demo mode; queuing is the privileged write.

**Why this can't become the unauthenticated-RCE path that was flagged as
the risk of building this before auth existed:** queuing always requires
`-auth-token` to be configured *and* a valid bearer credential with at
least the `remediate` role -- there is no "open" mode for remediation
the way board writes have one. Even a bug that let an attacker queue an
arbitrary string as `verb` couldn't run arbitrary code: the agent
scripts only implement `case` branches for the verbs in
`internal/remediate/actions.go`, never a generic "run this" path, and
`arg` is restricted to the same safe-token charset as everything else on
the wire, never assembled into a shell command line from untrusted
network input.

A human calling the API is no longer the only thing that can queue an
action, either -- see "Policy rules & the background evaluator" below
for the unattended path, gated the same way, through the same
allow-list, with an audit entry either way.

## Compliance posture scoring

```
GET /api/hosts/{host}/posture
```

An on-demand, 0-100 compliance score (`internal/policy.ComputePosture`)
computed fresh from whatever facts are on hand right now -- never
stored, never cached, so it always reflects the host's current state.
Deliberately small and honest about what it isn't: a heuristic over a
handful of concrete, observable signals, not a claim of formal or
audited compliance.

Starting at 100, it subtracts only for something it can actually see:

- **-40, stale.** The host hasn't reported within the staleness
  threshold (`internal/policy.StaleAfter`, 24h) -- the same rule
  `/api/hosts?stale=true` and the board's `STALE` badge already use.
- **-20, firewall off.** Linux: `ufw_status` in the `firewall_av_status`
  fact is `"inactive"`. Windows: any profile's `*_enabled` field in that
  same fact is `"False"` -- one flat penalty per host even if multiple
  profiles are off, not stacked.
- **Up to -20, pending updates (Linux only).** 2 points per pending
  package in `patch_update_status.count`, capped at 20. Windows'
  `patch_update_status` reports installed hotfixes, not a pending count
  (see `cookWinHotfixes`'s doc comment), so there's nothing comparable
  to score there yet.

A category that was never collected is never penalized -- "unknown" and
"bad" are different things here. The response also carries a
`findings` list: a short, human-readable line per deduction, so a caller
never has to reverse-engineer a bare number.


Three frameworks ship today: **TopoTrace Baseline** (six checks from
TopoTrace's own signals), plus illustrative mappings onto the **HIPAA
Security Rule** and a **NIST SP 800-53** subset, each check named after
the control it draws evidence from -- there to prove the framework
abstraction is pluggable, not to claim a certified mapping. Pick one on
the Compliance tab or with `?framework=` on the summary endpoint; see
`docs/compliance.md`.

![Framework selector](docs/screenshots/compliance-frameworks.png)

![HIPAA mapping](docs/screenshots/compliance-hipaa.png)

## Vulnerability correlation

```
GET /api/hosts/{host}/vulnerabilities
```

Cross-references a host's `installed_software` fact against two
sources, merged: `internal/vuln`'s hand-curated static dataset (ten
real, well-documented CVEs against common Debian/Ubuntu packages --
Shellshock, Baron Samedit, the OpenSSH forwarded-agent RCE, and others,
each with a package name, a known-vulnerable version ceiling, a CVE ID,
a severity, and a one-line description), and, when enabled, a **live
feed from [OSV.dev](https://osv.dev)** (`internal/vuln/feed.go`) -- a
free, no-API-key vulnerability database Google runs, queried per
package in `vuln.Watchlist` against its Debian ecosystem.

The live feed is off by default -- start with `-vuln-feed` (or
`TOPOTRACE_VULN_FEED=true` in the systemd env file) and it refreshes on
`-vuln-feed-interval` (default 6h), making outbound HTTPS requests to
`api.osv.dev`. A refresh is best-effort: if OSV.dev is unreachable, the
last successful result stays in place rather than the feed going empty,
so a transient outage degrades to "static dataset only," not "no
coverage." `vuln.CheckWithFeed` is the merge point both the API handler
and the background evaluator's policy checks call through -- the static
dataset was never replaced, only supplemented, so this still works with
zero network access if you'd rather not enable it.

The version comparator (`compareVersions`) only handles a leading
numeric dotted segment plus a simple epoch-prefix strip, not full Debian
version semantics (`~` prerelease markers and vendor/build suffixes are
explicitly out of scope) -- true of both the static dataset and
whatever OSV.dev returns. Good enough to demonstrate real correlation
end to end against real, current CVEs; still not a substitute for a
dedicated vulnerability scanner.

**Unverified note:** `internal/vuln/feed.go`'s OSV.dev client (the HTTP
request/response shapes, the ecosystem name, the fixed-version parsing)
was written against OSV.dev's public API documentation, but
`api.osv.dev` was unreachable from the sandboxed environment this was
written in (egress-allowlisted to package registries only), so no live
query has actually been run against it yet. Enable `-vuln-feed` against
a real network and check the server log for a successful refresh (or
whatever error it reports) before relying on it.

## Importing a real scanner's findings

```
POST /api/scanner-import?format=nessus   # or qualys, generic; body is the CSV export
```

The version matching above is honest about being a demonstration.
Anyone who would actually deploy TopoTrace already owns a scanner, so
TopoTrace imports its output rather than pretending to replace it
(`internal/scanner`): a Nessus, Qualys or generic CSV export goes in,
and each finding is matched to a host by full name, short name, or an
IPv4 address from that host's `network_interfaces` fact. Matched
findings are stored as a `scanner_findings` fact -- an ordinary
`model.Fact`, so it is versioned and visible like any agent-collected
category -- which `internal/signals` merges into the host's findings,
so they flow through the identical compliance checks, risk factors,
fleet summary counts, CSV export and Ask TopoTrace context as TopoTrace's own
matches. Imported findings carry the scanner they came from, so a
compliance detail reads "2 known-vulnerable package(s); 1 imported
nessus finding(s)" rather than blurring the two.

Findings for hosts TopoTrace has never enrolled are reported back as
unmatched and deliberately not stored -- the scanner seeing an asset
TopoTrace does not know is the interesting part, and inventing host
records from a CSV would be worse than naming the gap. One import
replaces that host's previous `scanner_findings` fact, so re-importing
after a rescan is how it stays current.

The Compliance tab has the import form; the parsers are unit tested and
the whole path was exercised end to end (all three formats, matching by
FQDN/short name/IP, unmatched hosts, informational rows dropped, error
and authorization cases). What has *not* happened is an export from a
live Nessus or Qualys console: the sample CSVs were written to each
vendor's documented column layout, so a real export with an unexpected
column name may need the alias list in `internal/scanner.Parse`
extended. See `docs/scanner-import.md`.

![Importing a Nessus CSV export](docs/screenshots/compliance-scanner-import.png)

![A host's merged findings](docs/screenshots/host-vulns-imported.png)

## Shadow AI detection

```
GET /api/hosts/{host}/software-violations   # -> {"violations": [...], "shadow_ai": [...]}
```

Alongside the operator-defined software allow/deny lists above,
`internal/allowlist` ships a **built-in, pre-seeded ruleset**
(`ShadowAIPatterns`) flagging known AI desktop apps, CLI tools, and
browser-extension packages found in a host's
`installed_software` fact. No configuration required: every TopoTrace
deployment can answer "do we have unauthorized AI tooling anywhere"
on day one, the same "invisible SaaS/tool sprawl" problem enterprise
browser security products (this mirrors [Island](https://island.io)'s
governed-AI/shadow-AI framing) build shadow-IT detection around.

An AI tool an operator has explicitly sanctioned via a `Kind: "allow"`
software rule matching its name is excluded from shadow AI results --
approved software isn't shadow IT. That check is deliberately
independent of the generic allow/deny enforcement's own "an allow rule
switches on enforcement for its whole scope" behavior (see
`internal/allowlist.Evaluate`'s doc comment): sanctioning one AI tool
for a group never has the side effect of flagging every *other*
package in that scope as unauthorized.

Shadow AI detections are surfaced as their own labeled `shadow_ai`
field -- never lumped into the generic `violations` list -- at
`GET /api/hosts/{host}/software-violations`, as their own card on a
host's detail page in the dashboard, as a
`hosts_with_shadow_ai`/`total_shadow_ai_findings` stat tile on the
Fleet tab (`GET /api/summary`), and as their own TopoTrace Baseline
compliance check (`no-shadow-ai`, see "Compliance frameworks" in the
in-app Docs tab).

## Device trust for zero-trust access, behavioral signals, breach exposure

```
GET /api/trust/{host}?min=60     # readonly -- for a gateway, browser, or SSO policy
GET /api/signals?days=7          # admin -- UEBA-lite over the audit trail
GET /api/breaches?domain=x.com   # admin -- Have I Been Pwned
```

**Device trust.** Everything above reports on posture; this is the
endpoint that lets something else act on it. `internal/trust` turns the
blended risk score into a verdict a ZTNA gateway, an enterprise browser,
a VPN or an SSO conditional-access policy can ask for before granting a
device access: `score` (100 minus risk), `level`, `allow` against the
caller's own bar, the reasons, and the thresholds -- so the gate and the
person reading the audit trail see the same rule. A stale host is never
"trusted"; an unenrolled host is "untrusted," not a 404. Denied
decisions are audited. As an nginx `auth_request` it's roughly:

```nginx
location = /_topotrace_trust {
    internal;
    proxy_pass http://topotrace:8080/api/trust/$http_x_device_name?min=60;
    proxy_set_header Authorization "Bearer <readonly-key>";
}
# ... and a small script/Lua block turning {"allow": false} into a 403.
```

**Behavioral signals.** `internal/ueba` runs explainable heuristics over
TopoTrace's own audit trail -- the one dataset it already has about its
operators: writes outside business hours or on weekends, a burst of
writes, a run of remediations, mass deletes, a new admin-role API key,
a settings change, an actor nobody's seen before. Each signal names
the rule, the actor, the count and the audit entries. It's the UEBA
idea applied to TopoTrace's own users, and the doc comment says what a
real product adds on top (per-user baselines, peer groups, a scoring
model). Fleet tab, admin only.

**Breach exposure.** `internal/breach` asks Have I Been Pwned whether
an organization's domain shows up in known credential breaches. With
an HIBP API key (`-hibp-api-key`, paid, requires verifying the domain)
it lists every account on the domain found in a breach -- the signal
that matters for a fleet. Without one, it still returns the public list
of breaches of the domain itself and says plainly that's what it is.
The public lookup was exercised for real from this environment
(adobe.com, 152M accounts, 2013); the keyed lookup is unit-tested
against the documented response shape but not against a live key.
Compliance tab, admin only.

![Breach exposure](docs/screenshots/compliance-breach.png)

## OS lifecycle, certificate expiry, SBOMs & license sprawl

```
GET /api/hosts/{host}/lifecycle   # readonly -- OS end-of-life + certificate expiry
GET /api/hosts/{host}/sbom        # readonly -- CycloneDX 1.5 JSON download
GET /api/software/sprawl          # readonly -- fleet license/SaaS rollup
```

Four more answers from the inventory TopoTrace already has:

- **OS end of life** (`internal/eol`): a built-in table of vendor
  end-of-support dates (Ubuntu, Debian, Windows client and Server,
  macOS -- Apple publishes none, so those are marked estimates) checked
  against each host's `system_summary`. An OS past its date gets no
  security patches, so it's a `supported-os` compliance check, a risk
  factor, a Fleet tile and a host-page verdict. Hand-maintained and
  dated; check the vendor before relying on a row.
- **Certificate expiry** (`internal/certs`): the Linux and macOS agents
  collect server certificates from where they usually live (Let's
  Encrypt, nginx/apache/haproxy, the RHEL/Debian cert dirs -- never the
  CA bundle) via `openssl x509`; the Windows agent reads the machine
  Personal store. Expired and expiring-within-30-days certs become the
  `no-expiring-certificates` compliance check, a risk factor, a Fleet
  tile and a host-page list. The Linux collection was exercised for
  real against a self-signed cert here and cooked end to end through
  the air-gap path.
- **SBOM** (`internal/sbom`): each host's installed software as a
  CycloneDX 1.5 document with purls and its vulnerability findings
  attached, downloadable from the host page -- OS-package level, not a
  build-dependency SBOM, and the doc comment says so.
- **License & SaaS sprawl** (`internal/sprawl`): the same software
  inventory asked the finance question -- which commercial/SaaS desktop
  products are deployed, how many seats, and where three tools do one
  job (three video-conferencing clients, two IDEs). Illustrative
  catalog; the seam a real license inventory plugs into. Compliance tab.

![OS lifecycle and certificates](docs/screenshots/host-lifecycle.png)

![License and SaaS sprawl](docs/screenshots/compliance-sprawl.png)

## Config drift & golden baselines

```
GET    /api/hosts/{host}/baseline   # readonly -- drift report
POST   /api/hosts/{host}/baseline   # admin -- capture current facts as golden
DELETE /api/hosts/{host}/baseline   # admin
GET    /api/drift                   # readonly -- fleet rollup
```

Change history records every diff since the last report; policy and
compliance judge a host against rules. Neither answers "how far is this
box from the state we approved?" `internal/baseline` does: an operator
captures a host's facts as its golden baseline when it's known-good,
and from then on TopoTrace reports drift against it -- packages added or
removed, versions moved, services and ports changed, firewall flipped
-- item by item for list-shaped categories, so "vsftpd added" is one
line rather than a stringified array. Host page: capture/recapture/
clear plus the drift list; Fleet tab: how many baselined hosts have
drifted. The seed tool captures two baselines and drifts one of them.

![Config drift](docs/screenshots/host-drift.png)

## Browser extension inventory

```
GET /api/hosts/{host}/browser-extensions   # readonly
```

The browser is where most of an endpoint's sensitive work happens now,
and an extension with `<all_urls>` plus `webRequest`/`cookies` can read
every page and credential that passes through it. The Linux, macOS and
Windows agents enumerate every extension in every Chrome/Chromium/
Brave/Edge profile on the host and ship the raw `manifest.json` (base64,
parsed as real JSON server-side, localized names resolved) into a
`browser_extensions` fact. `internal/browserext` scores each one with
its reasons -- broad host access, sensitive permissions, the two
combined, sideloading, manifest v2, a curated deny-list -- and a curated
trusted list keeps ad blockers and password managers from scoring high
for permissions they legitimately need. Shows up on the host page, as a
Fleet tile, as a risk-score factor, and as the `no-risky-browser-
extensions` compliance check. See `docs/compliance.md`.

![Browser extensions](docs/screenshots/host-browser-extensions.png)

## Ask TopoTrace

```
go run ./cmd/topotrace -ai-api-key "sk-ant-..."                     # Anthropic
go run ./cmd/topotrace -ai-backend openai-compatible \
  -ai-base-url http://your-host:11434/v1 -ai-model qwen3:30b-a3b # a model you host
POST /api/ask   {"question": "which prod hosts have known vulnerabilities?"}
```

A natural-language query surface over the fleet data above -- but the
pitch is **governed AI**, not "there's a chatbot": every question asked
and the answer TopoTrace gave are recorded to the same audit trail every
other privileged action in this project already goes through
(`Store.RecordAudit`, truncated, actor-attributed the same way a board
write or a policy change is). `POST /api/ask` is gated at `readonly`
(asking a question is a read, not a write); left unconfigured (no
`-ai-api-key`/`TOPOTRACE_AI_API_KEY`), it answers with a clear `503 "not
configured"` error rather than ever making an outbound request with no
credential.

**The model backend is pluggable**, the same seam as SIEM forwarding.
`anthropic` speaks the Messages API; `openai-compatible` speaks the
chat-completions shape, which reaches Hugging Face's Inference
Providers router and equally an LM Studio, Ollama, vLLM or
text-generation-inference server on your own hardware, changing only
`-ai-base-url`. Either is switchable live from the Settings page with
no restart.

That second option is the one that matters here. Ask TopoTrace sends real
fleet context with every question: host names, addresses, installed
software, CVE findings, policy rules. Handing that to a third-party API
is precisely the objection a security-conscious buyer raises, and it is
a fair one. A model running on hardware the operator controls means the
inventory never leaves their network. The tradeoff is real too: a small
self-hosted model is worse at this than a frontier model, particularly
at drafting a valid policy rule, which is why `Validate` exists and why
both extra features fall back to non-AI paths. Reasoning models need
one more consideration: their hidden scratchpad spends the same token
budget as the answer, so this backend raises the floor and, if a model
still burns the lot thinking, says so plainly instead of returning a
blank. A non-reasoning build (Qwen3's `-instruct-2507` tags on Ollama)
avoids the problem and is faster besides.

![Ask TopoTrace backend selection](docs/screenshots/settings-ai-backend.png)

`internal/aiquery` builds a compact JSON snapshot straight from the
Store -- fleet summary, every host's posture score/findings, known
vulnerabilities, software-allowlist and shadow-AI violations,
compliance score, plus the configured policy rules, software rules,
and discovered-but-unmanaged assets, reusing the exact same
`complianceInput` computation the Compliance tab already uses so Ask
TopoTrace's answers are grounded in the same numbers the rest of the
dashboard shows -- then calls the configured backend (stdlib
`net/http` only, no SDK, same integration style as `internal/vuln`'s
OSV.dev client and `internal/oauth`'s token exchange) with that
context plus the question, instructing the model to answer only from
the supplied snapshot rather than invent hosts or findings. A small
chat-style panel on the dashboard's **Ask TopoTrace** tab is wired to the
endpoint directly.

**Unverified note, stated plainly:** this was built and reviewed
without a real Anthropic API key in hand -- `internal/aiquery`'s
request/response shapes were written against the Messages API's
documented contract and exercised against the "not configured" path
(no key set), but no live call has actually been made against
`api.anthropic.com` yet. Set `-ai-api-key` to a real key and ask it a
question before relying on it.


Ask TopoTrace also **drafts policy rules from plain English** (the Fleet
tab's "Or describe it" row fills the policy form for you to review and
create -- never creates on its own) and **writes the executive summary**
(a button on the Reports card, four paragraphs from the same data as the
printed report). Both fall back to keyword rules / a template without an
API key and say so. See `docs/ask-topotrace.md`.

![Draft a policy from a description](docs/screenshots/fleet-ask-draft.png)

## Policy rules & the background evaluator

Policies are what closes the loop the original "what's next" list
called out: an unattended, on-a-schedule check of every host against a
rule, that can queue a remediation action entirely on its own. A rule
(`model.Rule`) is one of exactly four fixed `Kind`s -- the same "small,
fixed allow-list, not a free-form expression language" philosophy as
`internal/remediate`'s verbs:

| Kind | Violated when |
|---|---|
| `stale` | The host hasn't reported within the staleness threshold. |
| `score_below` | Posture score (`internal/policy.ComputePosture`) is below `threshold`. |
| `category_missing` | `category` has never been reported for this host. |
| `vulnerabilities_found` | `internal/vuln.Check` finds at least one known-vulnerable installed package. |

A rule can optionally be scoped to one board `group` (empty means every
host, regardless of group) -- e.g. a stricter `score_below` threshold
for `prod` than for everything else. If `auto_remediate` names a known
`internal/remediate` verb, any host that violates the rule gets that
action queued automatically, validated against the allow-list and the
host's actual platform exactly the same way a human-queued action is.

```
# admin key or the master token required
curl -X POST localhost:8080/api/policies   -H "Authorization: Bearer some-shared-secret"   -d '{"name": "prod firewall check", "group": "prod", "kind": "score_below", "threshold": 80}'

curl localhost:8080/api/policies -H "Authorization: Bearer some-shared-secret"      # list (readonly)
curl -X DELETE localhost:8080/api/policies/1 -H "Authorization: Bearer some-shared-secret"
```

`internal/evaluator.Evaluator` runs this on a fixed interval (`-evaluator-
interval`, default 5m; even with no rules it still records each host's
score-history point), evaluating every host against every scoped-in
rule, recording an audit entry and firing a `policy_violation` webhook
for anything that violates, and -- when the rule has `auto_remediate`
set -- queuing the action, recording a second audit entry, and firing a
`remediation_executed` webhook, all without a human in the loop.
Creating or deleting a policy always requires real auth (the same
"never available in demo mode" gate as remediation itself, since a
policy with `auto_remediate` set carries the same risk).

**Alert dedup, snooze, and resolution.** The evaluator used to record
the same violation to the audit trail and re-fire the same webhook every
run -- every five minutes, forever -- which is the alert-fatigue failure
mode every detection product eventually has to solve. `internal/alerts`
now keeps the set of open (rule, host) violations between runs: a
violation is announced once when it opens, again every 24 hours while
it stays open, and once more (`policy-resolved` /
`software-violation-resolved` audit entries, a `violation_resolved`
webhook) when it clears. An auto-remediation is queued when the
violation is first announced, not re-queued every run. `GET /api/alerts`
is the deduplicated "what's wrong right now" list with first-seen and
occurrence counts; `POST /api/alerts/snooze` quiets one for N hours
(`remediate` role, audited). The Fleet tab's "Open violations" card
shows both.

**Approval gate.** A rule with `auto_remediate` can also set
`require_approval`. Instead of queuing the action, the evaluator parks
it as a pending approval (one per rule+host, however long the violation
persists), records a `remediation-proposed` audit entry and fires a
`remediation_proposed` webhook. `GET /api/approvals` lists them; `POST
/api/approvals/{id}/approve` queues the action exactly as proposed,
through the same `remediate.Validate` allow-list gate as every other
path, and `.../reject` drops it -- both `remediate` role, both audited.
The rule still detects and proposes; a person decides. The Fleet tab's
"Pending approvals" card is that decision.

![Approvals and open violations](docs/screenshots/fleet-approvals.png)

## Audit trail

```
GET /api/audit[?host=...&limit=N]   # admin role required; default limit 100
```

Every privileged write in the system -- a board group/tag change, a
group created, an action queued (by a human or by the evaluator), a
policy created or deleted, an API key created or deleted -- records who
(the credential's name, or `"master"`/`"anonymous"`), what, on what
target, and when. Gated at `admin`, not `readonly`, since an audit trail
is oversight tooling, not day-to-day operational data, on both store
backends (a real `audit_log` table with indexes on `target` and
`created_at` for pgstore, an append-only slice persisted to the JSON
snapshot for memstore).

## Notifications: webhooks, Slack, Teams, Jira, ServiceNow

```
go run ./cmd/topotrace \
  -webhook-url "https://example.com/hooks/topotrace" \
  -slack-webhook-url "https://hooks.slack.com/services/..." \
  -teams-webhook-url "https://....webhook.office.com/..." \
  -jira-url https://yourteam.atlassian.net -jira-email you@example.com -jira-token <api-token> -jira-project OPS \
  -servicenow-url https://dev12345.service-now.com -servicenow-user topotrace -servicenow-password <pw>
# every flag also reads its TOPOTRACE_* env var; every one is optional
```

`internal/webhook` fans every notable event -- `policy_violation`,
`software_violation`, `violation_resolved`, `remediation_proposed`,
`remediation_executed`, and `test` -- out to a set of **sinks**:

- **Generic webhook URLs** (`-webhook-url`, comma-separated): the raw
  event JSON (`{"type", "host", "detail", "timestamp"}`), the original
  behavior.
- **Slack** (`-slack-webhook-url`): an incoming webhook, `{"text": ...}`
  with the event as a bold title plus detail.
- **Microsoft Teams** (`-teams-webhook-url`): an incoming webhook /
  Workflows URL, sent as an Adaptive Card with a fact set.
- **Jira** (`-jira-url` + email/token/project): one issue per finding
  via the Cloud REST API v3 (`POST /rest/api/3/issue`, ADF description,
  `topotrace` + event-type labels).
- **ServiceNow** (`-servicenow-url` + user/password): one incident per
  finding via the Table API (`POST /api/now/table/incident`).

The ticketing sinks only accept the findings worth a ticket
(`policy_violation`, `software_violation`, `remediation_proposed`); the
chat and generic sinks take everything. All stdlib `net/http` against
each service's documented API -- no SDKs, same reason as the cloud
agents and SIEM forwarding. Each sink's payload is unit-tested against
an `httptest.Server`; none has been pointed at a real Slack/Teams/Jira/
ServiceNow tenant from this environment, so treat the exact field names
as "matches the docs," not "verified live."

**Durable queue.** Deliveries no longer go "one try, one retry, then a
warning." An event is written to the Store (a `notify_queue` document
per pending delivery) before any network call; a background worker
attempts each with exponential backoff (2s, 15s, 1m, 5m, 30m; six
attempts); a delivery that exhausts them is kept as a dead letter so an
operator can see what never arrived; a restart resumes whatever was
pending. `GET /api/notifications/queue` (admin) shows pending and dead
deliveries with attempts and last error; `POST /api/notifications/test`
(admin) delivers a synthetic event to every sink synchronously and
reports each outcome -- the Settings page's Notifications card is that
button. This is also what closes the long-standing "durable webhook
queue" backlog item.

![Notifications](docs/screenshots/settings-notifications.png)

## SIEM forwarding

```
go run ./cmd/topotrace -siem-hec-url https://splunk.example.com:8088 -siem-hec-token <hec-token>
# or: TOPOTRACE_SIEM_HEC_URL=... TOPOTRACE_SIEM_HEC_TOKEN=... go run ./cmd/topotrace
```

Forwards TopoTrace's entire audit trail (`internal/siemforward`) -- every
`Store.RecordAudit` call, so every policy violation, remediation, Ask
TopoTrace query, enrollment/key management action, and OAuth login, the
same events `GET /api/audit` shows -- to a real SIEM, fire-and-forget
with a 5-second timeout so a slow or unreachable SIEM can never block or
fail the request that triggered the event. Built on a small `Forwarder`
interface (`Send(ctx, event) error`) so a backend can be added without
touching any call site. Three exist today, chosen with
`-siem-backend` (`TOPOTRACE_SIEM_BACKEND`):

| Backend | Transport |
| --- | --- |
| `splunk-hec` (default) | HTTPS `POST` to `<url>/services/collector/event`, `Authorization: Splunk <token>`, `{"event": <audit entry>, "sourcetype": "topotrace", "time": <unix-ts>}` |
| `sumo-http` | `POST` of the event JSON to a Sumo Logic HTTP Logs Source URL, `X-Sumo-Category: topotrace/audit`, optional `X-Sumo-Token` |
| `logrhythm-webhook` | `POST` of the event JSON to a LogRhythm Open Collector webhook beat, optional bearer token |

All three are hand-rolled against each vendor's published ingestion
docs, stdlib `net/http` only -- same "no SDK, no module proxy access"
approach as every other outbound integration here. Splunk is the only
one that requires both a URL and a token; the other two take a URL
alone. The backend can be switched at runtime from the Settings page or
`PATCH /api/settings` with no restart, which was verified end to end
against a local capture server (a switch to `sumo-http` took effect
immediately and the next audit entry arrived at the new endpoint).
Payload construction is unit-tested against an `httptest.Server`
(`internal/siemforward/splunk_test.go`,
`internal/siemforward/backends_test.go`); none of the three is verified
against a live vendor tenant, since this dev environment has none to
test against. See `docs/siem-integration.md`.

## Server settings

```
GET /api/settings     # admin
PATCH /api/settings   # admin, checked strictly
```

`GET` is a one-stop snapshot of what this server is actually running
with -- storage backend (memstore/postgres, never the DSN), listen
addresses, evaluator interval, and whether auth/OAuth (plus its
role-map)/the vuln feed/Ask TopoTrace (plus its model)/webhooks (plus a
count)/SIEM forwarding (plus which backend) are configured. Never a
secret value itself -- `TOPOTRACE_AUTH_TOKEN`, `TOPOTRACE_POSTGRES_DSN`,
`TOPOTRACE_AI_API_KEY`, the OAuth client secret, and the SIEM HEC token are
all excluded by construction (see `internal/api/server.go`'s
`handleSettings`), only presence/absence and non-secret metadata about
each. Exists because today all of this lives in CLI flags/env vars with
nothing surfaced in the dashboard -- there was no single place to see
server-level config at a glance.

`PATCH` lets an admin credential turn SIEM forwarding and Ask TopoTrace on,
off, or reconfigure them from the Settings tab, with no restart:
`internal/siemforward.Dynamic` and `internal/aiquery.ConfigStore` are
swappable at runtime, and cmd/topotrace always wires both in (even when
starting with neither configured) so a later PATCH can enable them. The
change is also persisted to `<data-dir>/settings-overrides.json` (mode
0600) so it survives a restart -- unless the process was started with
the matching `-siem-hec-*`/`-ai-api-key` flag or env var already set,
which always wins over a saved override, so a value pinned at deploy
time can't be quietly overridden by something saved from the dashboard
in an earlier run. Every other setting (storage backend, listen
addresses, the auth token itself, OAuth, webhooks, the vuln feed) stays
flag/env-only by design -- see `docs/api-reference.md` for the full
field list. Everything else about this endpoint's response shape is
identical to `GET`'s.

## Score history, trends & time to remediate

```
GET /api/history?days=30            # readonly
GET /api/hosts/{host}/history       # readonly
```

Every score in TopoTrace used to be computed fresh per request and then
forgotten -- a host was compliant or it wasn't, right now, with no way
to say whether the fleet was getting better. The background evaluator
(`internal/evaluator`) now records one `internal/history` point per host
per run -- posture score, compliance score, vulnerability count, stale
flag -- into a capped per-host series (a `model.Document`, see
`internal/store`), and the Fleet tab draws the last 30 days as a trend
chart with a hover crosshair:

![Fleet trends](docs/screenshots/fleet-trends.png)

Each host page carries the same series as a sparkline:

![Host score history](docs/screenshots/host-history.png)

The same series is what makes **time to remediate** measurable: the
rollup finds every span where a host's compliance dipped below 100% and
later recovered, and reports mean/median hours over the window, how
many hosts are still open, and the oldest open span -- the metric a
security program gets asked about ("are we fixing things faster?")
that a snapshot tool can't answer. Each host's detail page shows its
own 30-day sparkline. `cmd/seed` backfills 30 days of synthetic history
(ending at each host's real current scores, with a few deliberate
"fell out, then fixed" incidents) so a demo instance has a trend to
show on day one.

## Risk scoring & baseline comparison

```
GET /api/hosts/{host}/risk   # readonly
GET /api/risk                # readonly
GET /api/benchmark           # readonly
```

Posture, vulnerabilities, Shadow AI and software violations were each
shown separately, which left the reader to work out that a critical CVE
on an internet-facing database is a different problem from the same CVE
on an internal build box. `internal/risk` blends them into one 0-100
score per host (higher is riskier): vulnerability severity points
(capped), posture deficit, staleness, Shadow AI and policy violations,
then multiplied by two facts only an operator knows -- how critical the
host is (`criticality:high` tag) and whether it's exposed
(`exposure:internet` tag, or the plain `public` tag the seed data uses).
Both come from the existing tag editor, no new schema. Every score
carries its factor breakdown so it's never a black box; the Fleet tab
ranks the riskiest hosts and the host page shows the factors.

![Risk and baseline](docs/screenshots/fleet-risk.png)

![Per-host risk factors](docs/screenshots/host-risk.png)

`internal/benchmark` puts the fleet's headline numbers next to a
reference baseline and says, per metric, whether this fleet is better or
worse. Stated plainly in the code, the API response, and the dashboard:
the baseline is illustrative -- hand-authored, plausible values for an
average mid-sized mixed fleet, not survey data and not a claim about any
real industry. It's the seam a licensed or collected dataset would plug
into.

## Entity map

```
GET /api/entities?types=host,cve&focus=<node id>&depth=2   # readonly
GET /api/entities/kinds                                    # readonly
```

TopoTrace already knew every one of these relationships; what it could not
do was show them together. A host page listed its vulnerabilities, the
Compliance tab listed software violations, another card listed risky
extensions, and nothing answered "which hosts share this CVE," "what
does this rule actually touch," or "is that extension on one machine or
half the fleet." Those are relationship questions and a list is the
wrong shape for them.

`internal/entitygraph` assembles the fleet into one traversable
picture: hosts, board groups, notable packages, CVEs, expiring
certificates, notable browser extensions and rules as typed nodes,
joined by typed edges (`member`, `installs`, `affected-by`,
`exposed-to`, `presents`, `governs`). Click any entity to pivot the map
around it, adjust the hop count, and read its relationships in words in
the detail pane. This is a different question from the Fleet tab's
network map below, which is about topology, so both exist.

![Entity map](docs/screenshots/entities-map.png)

The hard part was noise, not drawing. Fifteen hosts carry thousands of
installed packages, and a node per package per host is a hairball that
answers nothing, so a package earns a node only by being notable:
vulnerable, denied, shadow AI, or a licensed product in
`internal/sprawl`'s catalog. Certificates appear only when expiring or
expired, extensions only when risky or on more than one host. The rule
is that a node has to be either something an operator would act on or
something that links two hosts; a healthy certificate on one host is
neither. That turns thousands of packages into about twenty, and the
demo fleet into 62 entities and 82 relationships.

Color is the entity family, shape is the kind, a ring is status, and
size is how many things the entity touches. Three family colors rather
than seven kind colors, and that was measured rather than chosen: in a
node-link diagram any two nodes can end up side by side, so a palette
has to separate every possible pair. The seven hues a kind-colored
version needs fail a colorblind-separation check hard (worst pair 3.2
against a floor of 8, and 12.9 against a normal-vision floor of 15);
three hues pass comfortably (9.2 and 24.0). So nothing is identified by
color alone, status keeps its own reserved red and amber as a ring
rather than a fill, and every status is restated in words in the
tooltip, the detail pane and the table view. That table is a real view,
not a footnote:

![Table view of the same graph](docs/screenshots/entities-table.png)

Clicking a host shows what it is carrying and what governs it:

![One host's neighborhood](docs/screenshots/entities-focus.png)

Filtering has a subtlety the tab handles rather than hides. Ask for
hosts and CVEs only and the packages that join them are gone, which
would silently drop the very links the question was about, so a removed
intermediate entity's surviving neighbors are joined by a dotted
`indirect` edge instead. Only different families are joined, so a
package on fifteen hosts does not explode into a hundred host-to-host
edges.

Layout is a fixed-iteration force-directed relaxation with no
randomness at all (initial positions come from a stable sort, not a
seed), so the same fleet always lays out identically, followed by a
separation pass, a clamp and label assignment in that order. The
separation pass is the only reason several fleet-wide rules are visible
at all: four rules governing the same six groups are topologically
identical and otherwise settle on one point. Label placement tries four
positions per node, most-connected first, and skips a label rather than
drawing it over a neighbor; the names that lose are in the tooltip and
the table. See `docs/entity-graph.md`.

## Data model

```
go run ./tools/erd           # regenerate docs/data-model.{md,svg}
go run ./tools/erd -check    # fail if either is out of date
```

The static counterpart to the entity map: what TopoTrace persists and how
those shapes reference each other. Generated, because a hand-drawn ERD
is wrong within a month.

![Data model](docs/data-model.svg)

Entities and their fields are parsed straight out of
`internal/model/types.go`, so that page cannot drift from the code.
Relationships cannot be parsed, since Go has no foreign keys and this
project deliberately carries no ORM tags, so they are declared in the
generator and then validated against the parsed types: a declaration
naming a struct or field that no longer exists is a hard error, not a
quietly wrong diagram. The `Document` kinds are checked the same way,
against the packages that own them. `docs/data-model.md` has the full
field tables, the relationship list with cardinality, and the
document-kind table.

## Network map, "since last time", and the simulator

```
GET  /api/graph                    # readonly
POST /api/bookmarks                # remediate -- snapshot now
GET  /api/bookmarks/{id}/diff      # readonly -- what changed since
POST /api/demo/simulate            # admin -- fire a synthetic finding
```

**Network & assets.** `internal/graph` draws managed hosts (colored by
risk level) and discovered-but-unmanaged assets around the /24 subnet
each sits on (from the agent's `network_interfaces` fact, or the
discovery sweep's CIDR), falling back to board group for hosts that
report no interfaces, with a dashed edge from a discovered address to
the enrolled host it turned out to be. Layout is deterministic and
computed server-side; the Fleet tab just draws it and makes hosts
clickable. One picture instead of two lists.

![Network and assets](docs/screenshots/fleet-graph.png)

**Since last time.** `internal/bookmark` snapshots every host's
headline numbers under a name; later, "What changed?" diffs the
snapshot against the live fleet -- hosts added or gone, scores up or
down, findings new or fixed -- each line marked better or worse. Built
for opening a repeat demo with "here's what's new," equally for "what
did a week of patching actually change."

**Simulator.** The Settings page's Demo card fires synthetic events
through the same paths a real finding takes -- the audit trail (and so
SIEM forwarding), the notification queue, the behavioral signals --
so the "it happened, it forwarded to Slack, it opened a ticket" moment
can be shown on demand instead of waiting for a real host to misbehave.
Every synthetic entry is marked `(simulated)`; nothing touches host
facts or rules.

![Demo simulator](docs/screenshots/settings-demo.png)

## Reports & exports

```
GET /api/reports/executive                 # readonly -- print-ready HTML
GET /api/reports/compliance.csv            # readonly
GET /api/reports/risk.csv                  # readonly
GET /api/reports/vulnerabilities.csv       # readonly
GET /api/reports/audit.csv                 # admin
```

For the person who will never open the dashboard: `internal/report`
builds a one-page executive summary (headline stats, 30-day trend,
highest-risk hosts, known vulnerabilities, recent activity) as a
standalone HTML page laid out for the browser's own Print / Save as PDF
-- no PDF library, on purpose, so there's no rendering dependency to
own -- plus four CSV exports carrying exactly the numbers the dashboard
shows. The Fleet tab's "Reports & exports" card wires all five up
(fetching with the bearer token, since a plain link can't).

![Executive report](docs/screenshots/executive-report.png)

## Fleet dashboard

```
GET /api/summary   # readonly
```

A fleet-wide rollup -- total hosts, stale hosts, hosts broken down by
platform, average posture score across the fleet, and how many hosts
have at least one known-vulnerable package -- computed fresh on every
call the same way posture is, nothing precomputed or cached. The web
dashboard's new **Fleet** tab (alongside **Hosts** and **Board**) renders
this plus the configured policy list and, for an admin credential, the
most recent audit entries -- the aggregate view to check before drilling
into a specific host, whose own detail page now also shows its posture
score and vulnerability findings inline.

## Agent health

```
GET /api/agents/health   # readonly
```

"Stale" says a host hasn't reported in 24 hours. `internal/agenthealth`
watches the collectors themselves: every report attempt over every path
(TCP, mobile, cloud, air-gap) records a check-in with how many changes
it carried, and every failure (bad or missing token, unextractable
payload, cook error) records why -- so the Agents tab can say the agent
that usually reports every 30 minutes is 3 hours late, or that
something has been presenting a wrong token for `badbox` for an hour
without one success. Cadence is the median of the last 20 gaps;
"late" is more than twice that. Verified live with a real air-gapped
report and a deliberately bad-token TCP upload.

![Agent health](docs/screenshots/agents-health.png)

## Public status page

```
GET /status        # unauthenticated, aggregates only
GET /status.json
```

A trust-page-style status view for a customer, an auditor or a manager:
how many hosts, what percent are fully compliant, average scores, open
findings, findings resolved this week, which integrations are on and
when the evaluator last ran -- and nothing else. No host names, no
findings, no people, by construction. `-public-status=false` turns it
off.

![Status page](docs/screenshots/status-page.png)

## Agent enrollment & the Agents tab

```
GET    /api/enrollments          # admin
POST   /api/enrollments          # admin -- {"host": "...", "platform": "..."}
DELETE /api/enrollments/{id}     # admin
GET    /api/agents/download/{platform}   # unauthenticated -- linux, macos, or windows
```

Rather than TopoTrace reaching out and pushing agents onto remote hosts
(which would mean this server holding SSH/WinRM credentials and running
arbitrary remote code -- a materially bigger trust boundary than
anything else here), "deploy an agent from the interface" means
**tracked, self-service enrollment**: the web dashboard's **Agents** tab
mints a named, host-scoped, revocable token, the operator copies a
one-line install command (or a mobile app's setup values) onto that
host themselves, and the host reports in under its own steam from then
on -- the same trust model the rest of TopoTrace already uses for the
`-auth-token` credential, just narrowed to one host.

An enrollment token is deliberately **narrower** than the master
`-auth-token`/an admin API key: it authorizes only that one host's fact
reports (the TCP `TOPOTRACE1` upload or `POST /api/mobile-report`), never
remediation-result reporting, never any other API call. It flips from
`pending` to `enrolled` automatically the first time that host reports
in (`internal/ingest/server.go`'s `authorizedUpload`, `internal/api/
server.go`'s `authorizedIngestToken` -- both hash the presented token
with SHA-256 and match it against the stored hash, never storing or
logging the raw token itself after creation). Revoking it from the
Agents tab (`DELETE /api/enrollments/{id}`) immediately stops that host
from reporting -- a lost or decommissioned device stops trusting the
server, not the other way around.

`GET /api/agents/download/{platform}` serves the actual, real
`agent/{linux,macos,windows}/topotrace-agent.{sh,ps1}` scripts straight out
of the binary (embedded via `agent/embed.go`'s `//go:embed` -- the exact
committed scripts, never a separate copy that could drift) -- this is
the same download the Agents tab's per-platform install snippet points
at. It's intentionally unauthenticated: the script itself is not a
secret, only the enrollment token pasted into the install command is.

## Mobile & ChromeOS reporting (Android, iOS & ChromeOS)

```
POST /api/mobile-report   # host-scoped enrollment token (or the master token/an admin key)
```

A JSON-over-HTTP alternative to the raw `TOPOTRACE1` TCP protocol, for
agents where a socket-plus-tar.gz payload is the wrong shape:

```json
{"host": "pixel-8", "platform": "android", "facts": {"system_summary": {"os": "android", "...": "..."}}}
```

Facts feed into the exact same `UpsertHost`/`UpsertFact` path every
other agent's report goes through -- change tracking, staleness,
posture scoring, and policy evaluation all just work, no separate
mobile-only code path past this one handler
(`internal/api/server.go`'s `handleMobileReport`).

- **Android**: a real native app in `agent/android/` (Kotlin, WorkManager
  for periodic background reporting, BatteryManager/StatFs/
  ConnectivityManager for device facts). Build it in Android Studio --
  see `agent/android/README.md`, including exactly what's been verified
  by a real compiler in this pass (the JSON encoder and the
  `HttpURLConnection`-based networking layer, both pure-JDK code with no
  Android SDK dependency, compiled and smoke-tested with a plain
  `kotlinc`) versus what still needs a real Gradle/Android Studio build
  to confirm (everything touching `android.*`/`androidx.*`).
- **iOS**: no native app -- Apple's sandboxing rules out a true
  background agent outside MDM enrollment, which is out of scope here.
  `agent/ios/README.md` is a full no-code walkthrough for wiring the
  built-in **Shortcuts** app's Personal Automations to POST a device
  report on a schedule, plus the honest limitations of that approach
  (no true background execution, at most a few reports a day, no
  remediation).
- **ChromeOS**: a Manifest V3 Chrome extension in `agent/chromeos/`
  (`chrome.enterprise.deviceAttributes`/`networkingAttributes` for
  device serial/asset ID/MAC, `chrome.system.cpu`/`memory`/`storage` for
  hardware, `chrome.alarms` for a 30-60 minute reporting cadence,
  `chrome.storage.managed` so config is pushed by IT via the Google
  Admin console rather than typed in by a user). Built as its own
  extension rather than reusing the Android agent via ARC++ --  ARC++
  would report ChromeOS as "an Android app," not give it a distinct
  identity, which defeats the point (see `agent/chromeos/README.md`'s
  "Why an extension, not the Android agent via ARC++"). Unverified
  against a real managed Chromebook -- see that same README's "What's
  actually verified" section, the same "no real account to test
  against" caveat the cloud agents (`agent/aws`, `agent/azure`,
  `agent/gcp`) already carry.

All three are new surface area added to the fixed platform-string
convention `Host.Platform` already used ("linux", "windows", "darwin",
...) -- `"android"`/`"ios"`/`"chromeos"` need no special-casing anywhere
else: posture scoring, policy evaluation, and vulnerability correlation
all already treat an unrecognized category or platform as "no opinion,"
not an error (see `internal/policy/policy.go`'s `ComputePosture` doc
comment).

## What each agent collects

Both agents report `system_summary` (CPU/memory/OS/hostname -- the
original five/four capture files each platform started with) plus eight
more categories, each its own fact via the same `UpsertFact`/change-
tracking path `system_summary` always used -- `GET /api/hosts/{host}`
returns all of them, `GET /api/hosts/{host}/facts/{category}` fetches one
directly. Every category is independently best-effort: a command that
isn't installed, or a source that's unreadable, just means that one
category is absent from a given cook run, not a failed run.

| Category | Linux source | Windows source |
|---|---|---|
| `disk_usage` | `df -Pk` | `Win32_LogicalDisk` |
| `installed_software` | `dpkg -l` | Uninstall registry keys |
| `running_services` | `systemctl list-units --state=running` | `Get-Service` |
| `listening_ports` | `ss -tln` | `Get-NetTCPConnection -State Listen` |
| `local_users` | `/etc/passwd` | `Get-LocalUser` |
| `network_interfaces` | `ip -o addr show` | `Get-NetIPAddress` |
| `scheduled_tasks` | the agent's own `crontab -l` | `Get-ScheduledTask` |
| `patch_update_status` | `apt list --upgradable` (pending) | `Get-HotFix` (**installed**, not pending) |
| `firewall_av_status` | `ufw status` | `Get-NetFirewallProfile` |
| `browser_extensions` | every Chrome/Chromium/Brave/Edge profile's `Extensions/*/*/manifest.json` (also macOS) | same, under `AppData\Local\...\User Data` |
| `tls_certificates` | `openssl x509 -enddate` over Let's Encrypt / nginx / apache / haproxy / `/etc/pki/tls/certs` / `/etc/ssl/private` (also macOS) | `Cert:\LocalMachine\My` |

Two honest asymmetries, stated rather than papered over: `patch_update_
status` answers "what's outstanding" on Linux (apt already knows what's
upgradable) but "what's already installed" on Windows (the real pending-
update list needs the Windows Update COM API -- a materially bigger
piece of work, not done in this pass). And `installed_software`/
`installed patches` on Windows come from the registry/`Get-HotFix`
rather than the also-real `Win32_Product` WMI class, which triggers an
MSI consistency check against every installed package and is slow enough
on a real machine to be a bad default for something that runs on a
schedule.

Windows captures go out as CSV (`ConvertTo-Csv -NoTypeInformation`,
parsed with Go's `encoding/csv`) rather than the flat `Key: Value` format
`system_summary`'s files use, since these are naturally N-row categories,
not single-record ones -- see `internal/cook/windows_extra.go`. Linux
captures stay plain command output, parsed the same line-oriented way as
`system_summary`'s -- see `internal/cook/linux_extra.go`.

`browser_extensions` is the one category with the same capture format
on every platform: tab-separated browser, user/profile, id, version,
base64 `manifest.json`, base64 English `messages.json`, parsed once by
`internal/cook/browserext.go` for all three. It is the only category
the macOS agent collects beyond `system_summary`. The Linux collection
was exercised for real against a fake Chrome profile in this
environment; the Windows and macOS blocks are reviewed but unverified
on a real machine, the same class of caveat as the rest of those agents.

List-shaped categories (including this one) render as sub-tables on
the host page; `browser_extensions` additionally gets its own scored
card (see "Browser extension inventory").

## Metrics

```
GET /metrics
```

A hand-written Prometheus text-exposition endpoint -- no client library,
since three gauges don't justify a dependency (and it keeps `go.mod`'s
"nothing needs the network to build" story simple, see the vendoring
note above). It reports:

- `topotrace_hosts_total` -- total hosts TopoTrace has ever received a report
  from.
- `topotrace_hosts_stale_total` -- hosts that haven't reported within the
  staleness threshold (`internal/policy.StaleAfter`, 24h) -- the same
  rule the board's `STALE` badge and `GET /api/hosts?stale=true` use, so
  the three agree by construction rather than by convention.
- `topotrace_hosts_by_platform{platform="..."}` -- one gauge per platform
  currently reporting (`linux`, `windows`, `darwin`, ...).

Point a real Prometheus at it with an ordinary `scrape_config` job the
same way you would any other exporter. Unauthenticated, matching
`/healthz`'s posture -- host counts aren't a sensitive write path the
way remediation or board edits are, so it isn't gated behind
`-auth-token`.

## File headers

Every source file (Go, JS, CSS, HTML, shell, PowerShell, SQL, Kotlin,
YAML) carries a TopoTrace LLC header -- file, one-line
brief drawn from the file's own leading comment, project, author, the
file's first-commit date, version, and the copyright line. The code is
Apache 2.0-licensed (see `LICENSE` and `NOTICE`); the header says so rather than
claiming the code is confidential. `go run ./tools/fileheader` stamps
any new file that's missing it (idempotent), and `go run
./tools/fileheader -check` exits non-zero if one is, for CI.

## Testing

```
go test ./...
```

`internal/cook/linux_test.go` verifies the Linux parser against the
bundled synthetic capture files in `testdata/linux-demo-host/`.
`internal/store/memstore`'s tests run unconditionally (no setup needed).

`internal/store/pgstore`'s tests are real integration tests against a
real Postgres -- not mocked -- and are skipped unless you point them at
one:

```
export TOPOTRACE_TEST_POSTGRES_DSN="postgres://topotrace:topotrace@localhost:5432/topotrace_test?sslmode=disable"
go test ./internal/store/pgstore/...
```

They drop and recreate the schema at the start of every run, so don't
point that env var at a database with data you care about. Any local
Postgres 13+ works -- there's nothing Docker-specific about it.

## What's here vs. what's next

Done, and working end to end: TCP ingest with a real framed protocol,
tar.gz extraction with zip-slip protection, Linux and Windows cook
parsers, change-tracked storage behind a swappable interface -- with a
real Postgres implementation as well as the in-memory one, both proven
against a live database, not just by inspection, and a real embedded
migration runner (`pgstore/migrate.go` + `migrations/*.sql`) instead of
a single apply-on-every-startup schema file -- a queryable REST API, a
branded web dashboard with a Hosts view, a Kanban board with
drag-and-drop grouping, persisted columns (`groups` table,
`/api/groups`), tagging, and a change-history timeline, and now a Fleet
summary view, server-side staleness (`internal/policy`,
`/api/hosts?stale=true`) backing both the board's `STALE` badge and a
hand-written `/metrics` Prometheus endpoint, real one-shot agents for
Linux, Windows, and macOS, bare-metal scheduling for the Linux and
Windows agents (a systemd timer, a Windows Scheduled Task), a Helm chart
running the whole thing (server, Postgres, and the Linux agent as a real
scheduled CronJob) on Kubernetes, eight more agent-reported fact
categories beyond system_summary, and a full second phase on top of all
of that: named role-scoped API keys and a real `readonly`/`remediate`/
`admin` RBAC layer (replacing "one shared token, one trust level"), a
per-host compliance posture score, group-scoped policy rules evaluated
on a schedule with unattended auto-remediation, vulnerability
correlation against installed software, a real audit trail, SIEM-style
outbound webhooks, and a fleet-wide summary endpoint and dashboard tab
(see "Authentication, roles & remediation", "Compliance posture
scoring", "Vulnerability correlation", "Policy rules & the background
evaluator", "Audit trail", "Webhooks", "Fleet dashboard", "What each
agent collects", and "Metrics" above), and a third phase: self-service
tracked agent enrollment with revocable host-scoped tokens, a
`POST /api/mobile-report` JSON ingest path, a native Android agent app
and a documented iOS Shortcuts-based reporting flow, a live OSV.dev
vulnerability feed layered on top of the static dataset, and a
standalone systemd deployment path alongside the Helm chart (see "Agent
enrollment & the Agents tab", "Mobile & ChromeOS reporting (Android, iOS & ChromeOS)",
"Vulnerability correlation", and "Standalone (Linux VM / bare metal,
systemd)" above), and a fourth phase, aimed at a first soft release:
software allow/deny lists scored per host, framework-based compliance
tracking (CIS-style checks against collected facts, a per-host score,
and a fleet-wide summary), an in-app Docs page and dashboard tabs for
both of those, a CIDR/target-list network discovery scanner
(`cmd/discover`) that reports open ports and banners for devices that
aren't enrolled hosts at all (`model.DiscoveredAsset`, distinct from
`model.Host` -- see `docs/agents.md`), an air-gapped reporting path
(`--airgap-out`/`-AirgapOut` on the existing Linux/Windows agent
scripts, base64-encode instead of send, paste into the Agents tab or
`POST /api/airgap-report`), three stdlib-only cloud-inventory scanners
for AWS/Azure/GCP reporting to a new master-token-only
`POST /api/cloud-report` (see `docs/agents.md`'s "Cloud agents"
section), and OAuth2/OIDC browser login for the dashboard alongside
the existing bearer-token schemes (see "OAuth2/OIDC dashboard login"
above).

This fourth phase was built in one overnight sprint in a dev
environment with no Go compiler at all (confirmed: no `go` binary, no
Docker, no way to build one) -- every file in it was hand-verified
(brace/paren/import balance, cross-checked against existing code
patterns) but **not one line of it has been compiled or run**, with
exactly one exception: the air-gap flag on the agent scripts, which
*was* actually executed end to end (a real capture, base64-encoded,
decoded, and extracted back into the expected file layout), because
bash/tar/gzip/python3 are real, runnable tools here even though `go
build` is not. Treat every other new file in this phase --
`internal/oauth`, `cmd/discover`, `agent/aws`, `agent/azure`,
`agent/gcp`, and the discovery/air-gap/cloud-report additions to
`internal/api`, `internal/store`, and `internal/model` -- as reviewed-but-
unverified until you've actually built and run this repo yourself.
That's not a hedge to bury in fine print: it's the honest status, and
it's why this section says so plainly instead of just listing the
features as "done."

And a fifth phase, aimed squarely at a security-company interview demo:
`cmd/seed` (a synthetic-but-realistic 15-host fleet, one command),
built-in shadow AI detection layered onto the existing software
allow/deny lists (`internal/allowlist.ShadowAIPatterns`, its own
labeled category everywhere the dashboard shows allowlist violations),
and "Ask TopoTrace" (`POST /api/ask`, `internal/aiquery`, a governed-AI
natural-language query surface over the fleet data with every
question+answer recorded to the audit log) -- see "Shadow AI
detection" and "Ask TopoTrace" above, and "Demo seed data" under "Running
it." Unlike the fourth phase above, this one *was* built with a real
Go toolchain on hand: every new and changed file passes `go build
./...` and `go vet ./...`, `go test ./...` still passes (including a
new `internal/allowlist` test for shadow AI detection and its
allowlist-suppression behavior), and the seed tool, the Shadow AI
endpoints, and the dashboard's new Fleet/host-detail UI were all
smoke-tested end to end against a real running server. The one piece
that couldn't be verified live: `internal/aiquery`'s actual call to
`api.anthropic.com` -- built with no real Anthropic API key in hand
this pass, so only its request/response shapes and the "not
configured" error path are proven; see "Ask TopoTrace"'s own unverified
note above.

And a sixth round: a fix for the Docs tab (a JSON key-casing mismatch
between `docs.Index`'s untagged Go struct fields and `app.js`'s
lowercase reads, so every doc page 404'd on `/api/docs/undefined` --
see "Server settings" above's neighbor, and `docs/embed.go`'s `json`
tags), the `GET /api/settings` server-configuration snapshot, SIEM
forwarding to Splunk HEC (`internal/siemforward`, see "SIEM forwarding"
above), and the ChromeOS extension (`agent/chromeos/`, see "Mobile &
ChromeOS reporting" above). Verified live this round: the Docs-tab bug
was root-caused by code review (not a browser repro) -- `curl`ing
`/api/docs`/`/api/docs/getting-started` against the running server
showed the backend was already fine, and `app.js`'s `showDocs()` was
reading `p.name`/`p.title` against a response actually shaped
`{"Name", "Title"}`, sending every doc-page fetch to
`/api/docs/undefined` -- then the fix (`json` tags added to
`docs.Index`) was confirmed live: rebuilt, redeployed, and re-curled,
now returning lowercase keys. `GET /api/settings` was also curled
against the running server post-deploy. `go build ./...`/`go vet
./...`/`go test ./...` all passing
including new `internal/siemforward` tests
(`splunk_test.go` against a real `httptest.Server`, `store_test.go` for
the audit-forwarding wrapper). Not verified: the Splunk HEC forwarder's
actual delivery to a real Splunk instance (no instance to test against,
same as every other outbound integration here), and the ChromeOS
extension itself -- reviewed by hand against Chrome's published
extension API docs, but never loaded on a real Chromebook or exercised
against a real Google Workspace admin console, the same "no real
account to test against" caveat the cloud agents already carry (see
`agent/chromeos/README.md`'s "What's actually verified" section for the
detailed breakdown).

Deliberately not done yet, in rough priority order:
- **Real-device/real-instance verification for the sixth phase** -- the
  ChromeOS extension has never run on a real Chromebook or against a
  real Google Workspace admin console (see `agent/chromeos/README.md`),
  and the Splunk HEC forwarder has never delivered to a real Splunk
  instance (payload construction is unit-tested against
  `httptest.Server`, not a live HEC endpoint). Treat both as "should
  work, reviewed and locally tested, not yet proven against the real
  thing."
- **LogRhythm and Sumo Logic SIEM backends** -- `internal/siemforward`'s
  `Forwarder` interface is designed for this (see "SIEM forwarding"
  above and `docs/siem-integration.md`), but only Splunk HEC is actually
  implemented this round.
- **A real compiled/run verification pass on the fourth phase** --
  see the paragraph just above. This is the single most important
  thing to do before trusting any of it: `go build ./...`, `go vet
  ./...`, and a live run against a real host, a real (or sandboxed)
  cloud account, and a real identity provider.
- **A live call through Ask TopoTrace with a real Anthropic API key** --
  see the fifth-phase paragraph above. `-ai-api-key`/`TOPOTRACE_AI_API_KEY`
  needs to actually be set to something real before this pitch is
  proven end to end, not just reviewed.
- **Real-device verification for this phase's newest pieces** — the
  Android app, the iOS Shortcuts flow, the live OSV.dev feed, and the
  systemd unit/install script were all written in an environment with no
  reachable Android SDK, no iOS device, and an egress allowlist that
  blocks Google/Maven's repositories and api.osv.dev outright (only
  `internal/vuln/feed.go`'s HTTP client shape and the Android app's
  pure-JDK networking/JSON layer got real compiler+runtime verification;
  everything else was hand-reviewed and is clearly flagged as such in
  its own README). Treat all four as "should work, not yet proven" until
  run for real, the same status the Windows/Ubuntu agents carried before
  they were verified against real hardware.
- **Remote-push agent deployment** — enrollment is self-service
  (a host reports in using a token an operator pastes onto it); TopoTrace
  never holds SSH/WinRM credentials and never pushes an agent onto a
  remote host or runs code on your behalf. A deliberate scope boundary,
  not a gap to close later — see "Agent enrollment & the Agents tab".
- **Finer-grained roles** — still exactly three fixed tiers
  (`readonly`/`remediate`/`admin`); scoped API keys now narrow a key to
  one board group, but per-verb scoping (a key that can only
  `restart-service`) is still not a thing.
- **Dashboard treatment for the eight newer fact categories** — collected,
  stored, diffed, and queryable via the API today; the web UI's card view
  still only has bespoke layout for system_summary (host detail now
  additionally shows posture and vulnerabilities, but the other seven
  categories are still generic key/value tables, not curated layouts).
- **Legacy Unix/appliance platforms** — AIX, HP-UX, F5 TMOS, Cyclades
  were considered and deliberately set aside -- there's no such hardware
  anywhere in this pipeline to build or test against, so it'd be pure
  speculation rather than the proven-for-real pattern every other
  platform here follows (Linux and Windows are hardware/CI-tested;
  macOS's agent and cook parser exist and are reasoned through carefully
  but, like the Windows agent originally was, not yet run against real
  hardware -- see agent/macos/README.md).
- **eBPF-based collection** — a lower-overhead alternative to the
  current poll-and-parse agents on modern Linux kernels, mentioned in
  the original wishlist alongside the telemetry-export item above (which
  is now real, see "Metrics" above) but not attempted here.
