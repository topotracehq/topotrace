# ai-governance plugin

**Commercial-candidate plugin** -- not part of the Apache-2.0 open-core
binary. This is the first plugin built on `internal/pluginhost`'s
out-of-process mechanism (see `docs/plugins.md`), proving that a
Commercial-only capability can live entirely outside the core binary.

It layers a simple approved-tools/approved-MCP-commands allowlist on
top of the Community `internal/aiagentinv` visibility data
(`GET /api/hosts/{host}/ai-agents`): the visibility layer scores and
shows every AI CLI tool and MCP server config it finds; this plugin
says which of those findings are actually out of policy.

## Build and run

```
go build -o ai-governance ./plugins/ai-governance
mkdir -p /var/lib/muster-plugins/ai-governance   # or wherever -- see AI_GOVERNANCE_DATA_DIR below
cp ai-governance /etc/muster/plugins/            # the core's -plugin-dir
```

The core (`muster -plugin-dir /etc/muster/plugins`) launches this
binary itself; it's not normally run by hand. For manual testing:

```
AI_GOVERNANCE_DATA_DIR=/tmp/ai-governance-data \
MUSTER_CORE_URL=http://127.0.0.1:8080 \
MUSTER_AUTH_TOKEN=<the core's admin bearer token> \
./ai-governance
```

It prints the handshake line to stdout and then blocks, serving RPC on
a Unix socket, exactly like any other plugin.

## Configuration

- `AI_GOVERNANCE_DATA_DIR` -- where `policy.json` (the allowlist) is
  kept. Defaults to `./data/ai-governance`. **Do not commit this
  directory** -- it's per-deployment state, like the core's own
  `-data-dir`.
- `MUSTER_CORE_URL` -- base URL of the running core (e.g.
  `http://127.0.0.1:8080`), used by `GET /violations` to call back
  into `GET /api/hosts/{host}/ai-agents` for a host's current findings.
- `MUSTER_AUTH_TOKEN` -- bearer token sent on that callback. Needs at
  least `readonly` role.

## Storage

A single JSON file (`policy.json`) under the data directory, written
atomically (temp file + rename). No SQLite, no dependency on the
core's Postgres -- a first slice's allowlist is small and low-write-
volume enough that a flat file is the simplest thing that's still
correct; see `governance.Store`'s doc comment if that changes later.

## API (mounted by the core at `/api/plugins/ai-governance/`)

- `GET policy` -- the current allowlist.
- `POST policy` -- `{"op":"add"|"remove","kind":"tool"|"mcp_command","value":"..."}`.
- `GET violations?host=<name>` -- findings for that host (fetched from
  the core) that aren't covered by the allowlist.

## Scope

Deliberately small: no alerting, no email, no approval-workflow UI.
The point of this first slice is proving a Commercial capability can
be built and shipped as a plugin at all -- those are future work on
top of the same mechanism.
