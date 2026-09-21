# Plugins

TopoTrace can load out-of-process plugins: separate executables the
core launches as subprocesses and talks to over local RPC, the same
general shape as Terraform/Vault plugins. The mechanism is stdlib-only
(`net/rpc`, `net/rpc/jsonrpc`) -- no third-party plugin framework, in
keeping with this codebase's dependency-free ethos (see the top-level
README).

## Why

Commercial features shouldn't have to live in the same binary as the
Apache-2.0 open-core just to ship. A plugin is a separate,
independently-licensed binary that extends the core through a small,
generic RPC/HTTP bridge instead of being compiled in behind a "this is
a Commercial candidate" comment.

The mechanism itself is general -- core can load *any* module through
it, Community or Commercial. Today it only ships Michael's own
Commercial modules (`plugins/ai-governance`); there's no public plugin
SDK, marketplace, or third-party distribution story yet, but the
protocol is designed so that could be added later without a rewrite.
Existing `internal/*` packages (`browserext`, `aiagentinv`,
`compliance`, etc.) are **not** being retrofitted into plugins right
now -- that's future work, out of scope for this round.

## Protocol

1. **Launch.** The core scans `-plugin-dir` for executable files and
   runs each one as a subprocess.
2. **Handshake.** On startup, a plugin writes one line to its own
   stdout:

   ```
   TOPOTRACE_PLUGIN_MAGIC_COOKIE_V1|1|/tmp/topotrace-plugin-xxxx/plugin.sock
   ```

   cookie (proves it's actually a TopoTrace plugin) | protocol version
   | path to a Unix domain socket it's now listening on. The core
   reads this line with a 10s timeout; a missing, malformed, or
   version-mismatched handshake fails that plugin's load -- logged as
   a warning, never fatal to server startup.
3. **RPC.** The core dials the socket and speaks `net/rpc` over
   `net/rpc/jsonrpc` (JSON-RPC over the socket, not gob) -- chosen over
   gob purely for debuggability: the wire traffic is human-readable if
   you ever need to `nc` the socket or read a capture, and the
   performance difference doesn't matter for a local, low-frequency
   control-plane call. Every plugin implements three RPC methods:
   - `Describe(struct{}, *PluginInfo)` -- name, version, the HTTP
     mount-point prefix it wants (e.g. `ai-governance`), and a
     description.
   - `HandleHTTP(PluginHTTPRequest, *PluginHTTPResponse)` -- a generic
     HTTP-over-RPC bridge (method, path, query, headers, body in;
     status, headers, body out). The core never needs to know anything
     about a plugin's own sub-API beyond this.
   - `Shutdown(struct{}, *struct{})` -- graceful stop.
4. **Mount.** A plugin that completes the handshake and Describe is
   mounted at `/api/plugins/{name}/` on the core's HTTP mux; every
   request under that prefix is proxied to `HandleHTTP`.
5. **Shutdown.** On server shutdown, the core calls `Shutdown` on each
   plugin, waits briefly, then kills the process if it hasn't exited.

All of this lives in `internal/pluginhost` (manager, handshake
parsing, HTTP bridge) -- a few hundred lines, not a framework. Plugins
themselves call `pluginhost.ServePlugin` to get the handshake and
socket-serving boilerplate for free (see `plugins/ai-governance`).

## Running plugins

```
topotrace -plugin-dir /etc/topotrace/plugins ...
```

or `TOPOTRACE_PLUGIN_DIR=/etc/topotrace/plugins`. Default is empty --
plugins are opt-in, so a default Community install is unaffected.
Every executable file found directly under that directory is launched
as a plugin.

`GET /api/plugins` lists currently-loaded plugins (name, version,
mount point) -- useful for debugging and eventually a settings UI.

## What this is not (yet)

No auth between core and plugin beyond the local Unix socket
(both run as the same local user -- the same trust boundary as any
other subprocess this server launches), no TLS, no hot-reload, no
plugin signing, no public SDK docs. Those are all things a real
third-party plugin ecosystem would need; this slice proves the
mechanism with one real feature, not the whole platform.

See `plugins/ai-governance/README.md` for the first plugin.
