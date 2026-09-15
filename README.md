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
    same as memstore's `strings.Contains`, not a glob. Schema is in
    `pgstore/schema.sql`, applied automatically (`CREATE ... IF NOT
    EXISTS`) on every startup.

  Nothing above this layer (`cook`, `api`) knows or cares which one is
  backing it -- that's the point of the interface. Pick with a flag, see
  "Running it" below.
- **`internal/api`** — REST API (stdlib `net/http`, Go 1.22+ pattern
  routing, no router dependency) over whatever the store holds. Beyond
  read endpoints, `PATCH /api/hosts/{host}` is the one write in the API
  surface: `{"group": "..."}` and/or `{"tags": [...]}` assign a host to
  a board column and/or freeform labels (see `Store.SetHostGroup`/
  `SetHostTags` -- deliberately separate from the cook pipeline's
  `UpsertHost`, so a re-cook can never clobber them). `GET
  /api/hosts/{host}/changes[?limit=N]` surfaces the change-tracking data
  every `UpsertFact` already records, newest first.
- **`internal/webui`** — the web dashboard: a dependency-free single-page
  app (plain HTML/CSS/JS, no build step, no framework) embedded into the
  binary via `embed.FS` and served from the same port as the API.
  Branded with the real Muster logo/icon assets (cropped and
  color-matched from source artwork, see `static/img/`). Two views:
  - **Hosts** (`#/`) — the grid, with per-platform icons, a host detail
    page, and a search bar over `/api/query`.
  - **Board** (`#/board`) — a Trello-style Kanban view: one column per
    `Host.Group` (plus an always-present "Ungrouped"), native HTML5
    drag-and-drop to move a card between columns (`PATCH`es the group),
    and a text field to start a new, empty column. Cards show tag
    labels and a `STALE` badge for anything that hasn't reported in
    over 24h (a display heuristic today, not a stored rule -- see
    "what's next"). The host detail page has editors for group and tags
    (add/remove, autosaves via the same PATCH endpoint) and a "Recent
    changes" timeline reading `/api/hosts/{host}/changes`.
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

The schema (`internal/store/pgstore/schema.sql`) is applied automatically
on startup -- no separate migration step for a fresh database.

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

By default: ingest on `:9090`, API on `:8080`, data under `./data`.

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

**Honesty note:** this script was written and verified as carefully as
possible without a Windows machine available -- the wire protocol and
the capture-file format it produces were proven end to end by feeding an
equivalent payload through `demoagent` on the Go side (see
`internal/cook/windows_test.go` and `testdata/windows-demo-host/`), and
that half is fully tested. The PowerShell itself has not been executed
on a real Windows host by me. Try it against a test/dev Muster instance
first, and please report back (or send a patch) if anything doesn't
match a real machine's `Get-CimInstance` output.

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
tar.gz extraction with zip-slip protection, one platform's worth of
parsing, change-tracked storage behind a swappable interface -- with a
real Postgres implementation as well as the in-memory one, both proven
against a live database, not just by inspection -- a queryable REST API,
a branded web dashboard, and a Kanban board with drag-and-drop grouping,
tagging, and a change-history timeline on top of it.

Deliberately not done yet, in rough priority order:
- **Persisted board columns** — an empty column you create on the board
  (typed but no host dropped into it yet) lives only in that browser
  tab's JS state, not the server; it's gone on reload. A `groups` table/
  `/api/groups` endpoint would make the column list itself a real,
  shared, persisted thing instead of being inferred from whichever
  hosts currently have a group set.
- **Auth on the ingest daemon** — currently any TCP client can report
  data for any host. Called out in code, not hidden.
- **Server-side staleness and a real policy/rule layer** — the board's
  `STALE` badge is a client-side `Date.now()` comparison today, not a
  stored rule, and there's no way to alert on it. The original project's
  reporting engine could flag hosts out of compliance with a rule (e.g.
  "unpatched kernel version" or "hasn't reported in 48h"); a small
  rule-evaluation layer over the same data `/api/query` and the board
  already expose is the natural next step, not a rewrite.
- **More platforms** — Linux and Windows have cook parsers now; macOS
  and others don't yet. The pattern (`internal/cook/<platform>.go`,
  dispatched from `pipeline.go`) is meant to make adding one mechanical.
- **Schema migrations for pgstore** — right now the schema is a single
  file of `CREATE`/`ALTER ... IF NOT EXISTS` statements applied on every
  startup, which is fine for a schema that only ever grows (that's
  exactly how group_name/tags were added to the hosts table). A real
  migration tool (e.g. golang-migrate) would replace that once a change
  needs more than "add a column."
- **Running agents on a schedule** — both `agent/windows/
  muster-agent.ps1` and `agent/ubuntu/muster-agent.sh` are genuine
  one-shot collectors (not synthetic test fixtures like `demoagent`),
  but they're run-by-hand today, not installed as a scheduled task
  (Windows) or cron/systemd timer (Linux) for unattended, recurring
  reporting. That's the natural next step for either.
