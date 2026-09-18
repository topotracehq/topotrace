# Muster

A hardware/software/configuration inventory system: lightweight agents
report data from managed hosts, a Go server ingests and parses it, and a
REST API answers questions like "which of my servers are running Ubuntu?"

This is a **from-scratch project**, written in Go, inspired by — but not
ported from — an older Perl system I modernized separately. The domain
(agents → central collector → parsed/"cooked" facts → queryable reports)
is the same well-worn shape a lot of inventory/config-management tooling
uses; the design and code here are new.

## Why this exists

Built as a portfolio project to demonstrate backend/systems Go: a
concurrent TCP network service, a text-parsing pipeline, a clean
storage abstraction, and a REST API — the kind of thing that shows up
directly in infrastructure, security, and observability tooling.

## Architecture

```
   agent  --TCP (MUSTER1 protocol)-->  ingest daemon  --tar.gz extract-->  raw/<platform>/<host>/<snapshot>/*.txt
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
  A tiny hand-rolled framed protocol (`MUSTER1 <platform> <host>
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
    default, and it's all `go run ./cmd/muster` needs.
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
    including a first run against a database built by an older muster
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
  Branded with the real Muster logo/icon assets (cropped and
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
- **`cmd/muster`** — the server binary: runs the ingest daemon, the API,
  and the web UI together, one process, shared store.
- **`cmd/demoagent`** — *not* a real agent. A minimal test client that
  packages a directory of already-captured text files and pushes them
  over the wire, so the whole pipeline is demoable without writing a
  real per-platform collector yet.
- **`agent/windows/muster-agent.ps1`** — a real, if minimal, Windows
  agent: a dependency-free PowerShell script that collects CPU/memory/OS/
  hostname facts via `Get-CimInstance`, packages them with Windows' own
  built-in `tar.exe`, and sends them over the same MUSTER1 protocol
  `demoagent` uses. See that file's header comment for full usage, and
  the honesty note under "Running it" below -- it's been written and
  reasoned through carefully but not run against a real Windows machine.
- **`agent/ubuntu/muster-agent.sh`** — the Linux counterpart: a
  dependency-free bash script that captures `/proc/cpuinfo`,
  `/proc/meminfo`, `uname -a`, `/etc/os-release`, and `uptime` (exactly
  what `internal/cook/linux.go` expects), packages them with `tar`, and
  sends them over MUSTER1 using bash's built-in `/dev/tcp` -- no
  netcat/socat needed. Unlike the Windows script, this one has actually
  been run end to end against a live server (see "Running it" below).
- **`charts/muster/`** — a Helm chart deploying the whole stack on
  Kubernetes: the server as a Deployment, Postgres as a StatefulSet with
  a PVC, and the Ubuntu agent as a real CronJob (closing the "scheduled
  execution" gap for real) with an optional one-pod-per-node DaemonSet
  variant, plus least-privilege RBAC and a NetworkPolicy scoping who can
  reach the raw ingest port. See `charts/muster/README.md` for the full
  design writeup (including exactly what the RBAC/NetworkPolicy/hostPID
  choices are actually for) and its own verification-status note.

## Running it

### Locally (Go toolchain)

Requires Go 1.22+ (uses `net/http`'s method+path pattern routing).
No external services required by default, no config beyond flags —
`go run` and go. (Postgres is opt-in, see below.)

```
go run ./cmd/muster
```

By default this uses `memstore` (in-memory, JSON-snapshotted to
`./data/muster.json`). To use Postgres instead, point it at a running
Postgres with `-postgres-dsn` (or the `MUSTER_POSTGRES_DSN` env var):

```
go run ./cmd/muster -postgres-dsn "postgres://muster:muster@localhost:5432/muster?sslmode=disable"
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
docker build -t muster .
docker run --rm -p 8080:8080 -p 9090:9090 -v muster-data:/app/data muster
```

Or with Compose, which also wires up a one-shot demo client:

```
docker compose up -d muster
docker compose --profile demo run --rm demoagent
```

`demoagent`'s Compose service talks to `muster:9090` (the Compose service
name, resolved via Docker's built-in DNS) rather than `localhost`, since
it's running as its own container on the same Compose network.

That brings up `muster` with the default memstore backend -- nothing
else needed. To run it against Postgres instead, bring up the `postgres`
service (behind its own profile, so it stays out of the way when you
don't want it) and point `muster` at it:

```
docker compose --profile postgres up -d postgres
MUSTER_POSTGRES_DSN="postgres://muster:muster@postgres:5432/muster?sslmode=disable" \
  docker compose --profile postgres up -d muster
```

`postgres` here is also the Compose service name/DNS entry, same idea as
`demoagent` talking to `muster:9090` above. Data persists in the
`muster-postgres-data` named volume across restarts.

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
or to try out Fleet/Compliance/Ask Muster with real variety on hand --
`cmd/seed` writes a realistic, varied synthetic fleet straight into the
Store: 15 hosts across Linux/Windows/macOS, a mix of compliant and
non-compliant posture, real-looking vulnerability findings against
`internal/vuln.Dataset`'s curated CVEs, three shadow AI detections plus
one generic software-allowlist violation, two hosts backdated past the
staleness threshold, a handful of policy/software rules, and a few
network-discovered-but-unmanaged assets.

```
go run ./cmd/seed              # writes into ./data/muster.json (memstore)
go run ./cmd/muster            # then (re)start the server to serve it
```

It talks to the Store directly with the same `-data-dir`/`-postgres-dsn`
flags `cmd/muster` itself takes -- see `cmd/seed/main.go`'s package doc
comment for exactly why (there's no "insert one host's worth of
arbitrary facts" HTTP endpoint in the API today) and for the one
honest timing caveat: against the default memstore backend this only
takes effect the next time `cmd/muster` (re)starts against the same
`-data-dir`, since memstore keeps its state in memory once loaded.
Point both at the same `-postgres-dsn` instead and it works against an
already-running server immediately, live, no restart needed.

### Testing with the Windows agent

To send data from an actual Windows machine instead of synthetic test
fixtures, copy `agent/windows/muster-agent.ps1` to it and run:

```
.\muster-agent.ps1 -MusterHost <ip-or-hostname-of-the-muster-server> -MusterPort 9090
```

It reports as the machine's real computer name by default (`-HostName`
to override), and needs nothing beyond what Windows already ships with
(PowerShell 5.1+, `tar.exe`) -- see the script's own header comment for
the full parameter list and design notes.

**Verified against a real machine:** this script has been run for real
against a live Windows 11 machine, reporting through a live Muster
server on Kubernetes -- not just proven end to end via `demoagent`
against synthetic fixtures (see `internal/cook/windows_test.go` and
`testdata/windows-demo-host/`, which is how the wire protocol and
capture-file format were originally proven before a real Windows host
was available). Real output on record: `system_summary` correctly
reported the machine's actual CPU model and Windows edition string,
and `disk_usage` correctly reported its actual C: drive capacity and
free space.

### Testing with the Ubuntu/Linux agent

Same idea for a real Linux box: copy `agent/ubuntu/muster-agent.sh` to
it and run:

```
./muster-agent.sh --muster-host <ip-or-hostname-of-the-muster-server>
```

It reports under the machine's real `hostname` by default (`--host-name`
to override), and needs nothing beyond bash, `tar`, and `gzip` -- see
the script's own header comment (or `--help`) for the full option list.

Unlike the Windows script, this one has been run for real: verified end
to end against a live Muster server, collecting actual `/proc/cpuinfo`,
`/proc/meminfo`, `uname -a`, `/etc/os-release`, and `uptime` output and
confirming via the API that it parsed into accurate CPU/memory/kernel/
distribution facts.

#### Don't have a spare Ubuntu box? Use the bundled test container

`agent/ubuntu/Dockerfile` packages the script into a plain Ubuntu image
so you can run it against your `muster` container without needing an
actual second machine -- a genuine run of the real script (its own
container's `/proc/cpuinfo`, `uname -a`, etc.), not a canned fixture
like `demoagent`:

```
docker compose up -d muster
docker compose --profile ubuntu-agent run --rm ubuntu-agent
```

That builds the agent image, runs it on the same Compose network as
`muster` (reachable at the `muster` hostname, same as `demoagent`
does), reports as host `ubuntu-container01`, and exits. Check it landed:

```
curl localhost:8080/api/hosts/ubuntu-container01
```

To report under a different name or point at a different server, pass
your own arguments after `ubuntu-agent` (this replaces the default
`command` entirely, so include `--muster-host` too):

```
docker compose --profile ubuntu-agent run --rm ubuntu-agent \
  --muster-host muster --host-name my-test-box
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
docker build -t muster:latest .
docker build -f agent/ubuntu/Dockerfile -t muster-ubuntu-agent:latest .
helm install muster charts/muster
```

Deploys the server (Postgres-backed by default, via a StatefulSet), a
CronJob running the real Ubuntu agent on a schedule, and RBAC/
NetworkPolicy scoped as described in `charts/muster/README.md` -- read
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
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o muster ./cmd/muster
sudo deploy/systemd/install.sh ./muster
```

Installs a `muster` system user, a systemd unit (`Restart=on-failure`,
starts on boot), and `/etc/muster/muster.env` for configuration -- same
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
go run ./cmd/muster -auth-token "some-shared-secret"
# or: MUSTER_AUTH_TOKEN=some-shared-secret go run ./cmd/muster
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
go run ./cmd/muster -auth-token some-shared-secret   -oauth-client-id "..." -oauth-client-secret "..."   -oauth-auth-url "https://accounts.google.com/o/oauth2/v2/auth"   -oauth-token-url "https://oauth2.googleapis.com/token"   -oauth-userinfo-url "https://openidconnect.googleapis.com/v1/userinfo"   -oauth-redirect-url "http://localhost:8080/api/auth/callback"   -oauth-role-map "admin@example.com=admin,*@example.com=readonly"
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
MUSTER1 connection agents already make on their normal reporting
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
   `MUSTER1-RESULT <token> <action-id> <ok|fail> <bytes>` plus a short
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
`MUSTER_VULN_FEED=true` in the systemd env file) and it refreshes on
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

## Shadow AI detection

```
GET /api/hosts/{host}/software-violations   # -> {"violations": [...], "shadow_ai": [...]}
```

Alongside the operator-defined software allow/deny lists above,
`internal/allowlist` ships a **built-in, pre-seeded ruleset**
(`ShadowAIPatterns`) flagging known AI desktop apps, CLI tools, and
browser-extension packages -- ChatGPT, Claude, Ollama, LM Studio,
GitHub Copilot, Gemini, Perplexity, and others -- found in a host's
`installed_software` fact. No configuration required: every Muster
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
Fleet tab (`GET /api/summary`), and as their own Muster Baseline
compliance check (`no-shadow-ai`, see "Compliance frameworks" in the
in-app Docs tab).

## Ask Muster

```
go run ./cmd/muster -ai-api-key "sk-ant-..."   # or MUSTER_AI_API_KEY
POST /api/ask   {"question": "which prod hosts have known vulnerabilities?"}
```

A natural-language query surface over the fleet data above -- but the
pitch is **governed AI**, not "there's a chatbot": every question asked
and the answer Muster gave are recorded to the same audit trail every
other privileged action in this project already goes through
(`Store.RecordAudit`, truncated, actor-attributed the same way a board
write or a policy change is). `POST /api/ask` is gated at `readonly`
(asking a question is a read, not a write); left unconfigured (no
`-ai-api-key`/`MUSTER_AI_API_KEY`), it answers with a clear `503 "not
configured"` error rather than ever making an outbound request with no
credential.

`internal/aiquery` builds a compact JSON snapshot straight from the
Store -- fleet summary, every host's posture score/findings, known
vulnerabilities, software-allowlist and shadow-AI violations,
compliance score, plus the configured policy rules, software rules,
and discovered-but-unmanaged assets, reusing the exact same
`complianceInput` computation the Compliance tab already uses so Ask
Muster's answers are grounded in the same numbers the rest of the
dashboard shows -- then calls the Anthropic Messages API (stdlib
`net/http` only, no SDK, same integration style as `internal/vuln`'s
OSV.dev client and `internal/oauth`'s token exchange) with that
context plus the question, instructing the model to answer only from
the supplied snapshot rather than invent hosts or findings. A small
chat-style panel on the dashboard's **Ask Muster** tab is wired to the
endpoint directly.

**Unverified note, stated plainly:** this was built and reviewed
without a real Anthropic API key in hand -- `internal/aiquery`'s
request/response shapes were written against the Messages API's
documented contract and exercised against the "not configured" path
(no key set), but no live call has actually been made against
`api.anthropic.com` yet. Set `-ai-api-key` to a real key and ask it a
question before relying on it.

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
interval`, default 5m; the loop no-ops entirely if no rules exist yet),
evaluating every host against every scoped-in rule, recording an audit
entry and firing a `policy_violation` webhook for anything that
violates, and -- when the rule has `auto_remediate` set -- queuing the
action, recording a second audit entry, and firing a
`remediation_executed` webhook, all without a human in the loop.
Creating or deleting a policy always requires real auth (the same
"never available in demo mode" gate as remediation itself, since a
policy with `auto_remediate` set carries the same risk).

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

## Webhooks

```
go run ./cmd/muster -webhook-url "https://example.com/hooks/muster,https://example.org/hooks/other"
# or: MUSTER_WEBHOOK_URLS=https://example.com/hooks/muster go run ./cmd/muster
```

A minimal generic outbound notifier (`internal/webhook`): on a
`policy_violation` or `remediation_executed` event, POST a small JSON
payload (`{"type", "host", "detail", "timestamp"}`) to every configured
URL. One attempt, one retry after a short delay, every failure logged --
not a durable queue, not exactly-once delivery, just best effort, and
loud about it when both attempts fail. A `Dispatcher` with no URLs
configured (the default) is a safe no-op, so nothing has to branch on
"are webhooks even on." (For a real SIEM specifically, see "SIEM
forwarding" below -- it forwards the full audit trail, not just these
two event types, and speaks Splunk HEC's actual wire format rather than
an ad hoc JSON shape.)

## SIEM forwarding

```
go run ./cmd/muster -siem-hec-url https://splunk.example.com:8088 -siem-hec-token <hec-token>
# or: MUSTER_SIEM_HEC_URL=... MUSTER_SIEM_HEC_TOKEN=... go run ./cmd/muster
```

Forwards Muster's entire audit trail (`internal/siemforward`) -- every
`Store.RecordAudit` call, so every policy violation, remediation, Ask
Muster query, enrollment/key management action, and OAuth login, the
same events `GET /api/audit` shows -- to a real SIEM, fire-and-forget
with a 5-second timeout so a slow or unreachable SIEM can never block or
fail the request that triggered the event. Built on a small `Forwarder`
interface (`Send(ctx, event) error`) so more backends can be added
without touching any call site; the one real implementation this round
is Splunk's HTTP Event Collector (a plain HTTPS `POST` to
`<hec-url>/services/collector/event`, `Authorization: Splunk <token>`,
`{"event": <audit entry>, "sourcetype": "muster", "time": <unix-ts>}`),
hand-rolled against Splunk's published HEC docs, stdlib `net/http` only
-- same "no SDK, no module proxy access" approach as every other
outbound integration here. LogRhythm and Sumo Logic are documented as
natural next backends (both accept similar HTTP-collector-style
ingestion) but not implemented yet -- see `docs/siem-integration.md`.
Payload construction is unit-tested against an `httptest.Server`
(`internal/siemforward/splunk_test.go`); not verified against a live
Splunk instance, since this dev environment has none to test against.

## Server settings

```
GET /api/settings     # admin
PATCH /api/settings   # admin, checked strictly
```

`GET` is a one-stop snapshot of what this server is actually running
with -- storage backend (memstore/postgres, never the DSN), listen
addresses, evaluator interval, and whether auth/OAuth (plus its
role-map)/the vuln feed/Ask Muster (plus its model)/webhooks (plus a
count)/SIEM forwarding (plus which backend) are configured. Never a
secret value itself -- `MUSTER_AUTH_TOKEN`, `MUSTER_POSTGRES_DSN`,
`MUSTER_AI_API_KEY`, the OAuth client secret, and the SIEM HEC token are
all excluded by construction (see `internal/api/server.go`'s
`handleSettings`), only presence/absence and non-secret metadata about
each. Exists because today all of this lives in CLI flags/env vars with
nothing surfaced in the dashboard -- there was no single place to see
server-level config at a glance.

`PATCH` lets an admin credential turn SIEM forwarding and Ask Muster on,
off, or reconfigure them from the Settings tab, with no restart:
`internal/siemforward.Dynamic` and `internal/aiquery.ConfigStore` are
swappable at runtime, and cmd/muster always wires both in (even when
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

Every score in Muster used to be computed fresh per request and then
forgotten -- a host was compliant or it wasn't, right now, with no way
to say whether the fleet was getting better. The background evaluator
(`internal/evaluator`) now records one `internal/history` point per host
per run -- posture score, compliance score, vulnerability count, stale
flag -- into a capped per-host series (a `model.Document`, see
`internal/store`), and the Fleet tab draws the last 30 days as a trend
chart with a hover crosshair:

![Fleet trends](docs/screenshots/fleet-trends.png)

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

`internal/benchmark` puts the fleet's headline numbers next to a
reference baseline and says, per metric, whether this fleet is better or
worse. Stated plainly in the code, the API response, and the dashboard:
the baseline is illustrative -- hand-authored, plausible values for an
average mid-sized mixed fleet, not survey data and not a claim about any
real industry. It's the seam a licensed or collected dataset would plug
into.

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

## Agent enrollment & the Agents tab

```
GET    /api/enrollments          # admin
POST   /api/enrollments          # admin -- {"host": "...", "platform": "..."}
DELETE /api/enrollments/{id}     # admin
GET    /api/agents/download/{platform}   # unauthenticated -- linux, macos, or windows
```

Rather than Muster reaching out and pushing agents onto remote hosts
(which would mean this server holding SSH/WinRM credentials and running
arbitrary remote code -- a materially bigger trust boundary than
anything else here), "deploy an agent from the interface" means
**tracked, self-service enrollment**: the web dashboard's **Agents** tab
mints a named, host-scoped, revocable token, the operator copies a
one-line install command (or a mobile app's setup values) onto that
host themselves, and the host reports in under its own steam from then
on -- the same trust model the rest of Muster already uses for the
`-auth-token` credential, just narrowed to one host.

An enrollment token is deliberately **narrower** than the master
`-auth-token`/an admin API key: it authorizes only that one host's fact
reports (the TCP `MUSTER1` upload or `POST /api/mobile-report`), never
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
`agent/{linux,macos,windows}/muster-agent.{sh,ps1}` scripts straight out
of the binary (embedded via `agent/embed.go`'s `//go:embed` -- the exact
committed scripts, never a separate copy that could drift) -- this is
the same download the Agents tab's per-platform install snippet points
at. It's intentionally unauthenticated: the script itself is not a
secret, only the enrollment token pasted into the install command is.

## Mobile & ChromeOS reporting (Android, iOS & ChromeOS)

```
POST /api/mobile-report   # host-scoped enrollment token (or the master token/an admin key)
```

A JSON-over-HTTP alternative to the raw `MUSTER1` TCP protocol, for
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

The web dashboard's card view still only has bespoke layout for
`system_summary`; the other eight categories are fully collected, stored,
diffed, and queryable today, just not yet given their own dashboard
treatment -- a real follow-up, not silently dropped scope.

## Metrics

```
GET /metrics
```

A hand-written Prometheus text-exposition endpoint -- no client library,
since three gauges don't justify a dependency (and it keeps `go.mod`'s
"nothing needs the network to build" story simple, see the vendoring
note above). It reports:

- `muster_hosts_total` -- total hosts Muster has ever received a report
  from.
- `muster_hosts_stale_total` -- hosts that haven't reported within the
  staleness threshold (`internal/policy.StaleAfter`, 24h) -- the same
  rule the board's `STALE` badge and `GET /api/hosts?stale=true` use, so
  the three agree by construction rather than by convention.
- `muster_hosts_by_platform{platform="..."}` -- one gauge per platform
  currently reporting (`linux`, `windows`, `darwin`, ...).

Point a real Prometheus at it with an ordinary `scrape_config` job the
same way you would any other exporter. Unauthenticated, matching
`/healthz`'s posture -- host counts aren't a sensitive write path the
way remediation or board edits are, so it isn't gated behind
`-auth-token`.

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
export MUSTER_TEST_POSTGRES_DSN="postgres://muster:muster@localhost:5432/muster_test?sslmode=disable"
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
and "Ask Muster" (`POST /api/ask`, `internal/aiquery`, a governed-AI
natural-language query surface over the fleet data with every
question+answer recorded to the audit log) -- see "Shadow AI
detection" and "Ask Muster" above, and "Demo seed data" under "Running
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
configured" error path are proven; see "Ask Muster"'s own unverified
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
- **A live call through Ask Muster with a real Anthropic API key** --
  see the fifth-phase paragraph above. `-ai-api-key`/`MUSTER_AI_API_KEY`
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
  (a host reports in using a token an operator pastes onto it); Muster
  never holds SSH/WinRM credentials and never pushes an agent onto a
  remote host or runs code on your behalf. A deliberate scope boundary,
  not a gap to close later — see "Agent enrollment & the Agents tab".
- **A durable webhook queue** — `internal/webhook` is one attempt plus
  one retry, in-memory, logged either way; an endpoint that's down for
  longer than that retry window silently misses events rather than
  catching up once it's back.
- **Finer-grained roles** — today it's exactly three fixed tiers
  (`readonly`/`remediate`/`admin`), the same "small, fixed set" choice
  `internal/remediate`'s verbs and `model.Rule`'s `Kind` both make;
  per-group or per-verb scoped keys (e.g. a key that can only remediate
  hosts in one group) don't exist yet.
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
