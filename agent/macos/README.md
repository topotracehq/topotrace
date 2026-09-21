# TopoTrace macOS agent

A minimal, dependency-free bash agent that scans a Mac and reports it to
a running TopoTrace server. See `topotrace-agent.sh`'s own header comment
(`./topotrace-agent.sh --help` prints it) for the full option list.

Deliberately smaller than the Ubuntu/Windows agents: `system_summary`
only (CPU model, core count, memory, macOS product name/version, kernel
version, uptime), not the eight newer feed categories those two have --
`internal/cook/darwin.go` doesn't parse those for this platform yet.
Extending both sides together, the same way each newer feed landed for
Linux/Windows together, is a natural next step once there's a real macOS
fleet to build and test against.

## Requirements

- bash (ships with macOS -- note it's Apple's old 3.2 build, not bash
  4+; the script is written to that constraint, see its own comments).
- `tar`, `gzip`, `sysctl`, `sw_vers` -- all standard on any Mac.
- Network access from this host to the TopoTrace server's ingest port
  (`9090` by default).

## Quick start

```bash
./topotrace-agent.sh --topotrace-host <server-ip-or-hostname>
```

## Verification status

Not run against a real Mac or a live server as part of building it --
there was no macOS host available in the environment this was written
in. The capture format it produces is the same generic "Key: Value"
shape `internal/cook/windows.go`'s already-tested parser reads, reused
directly by `internal/cook/darwin.go` rather than inventing a
macOS-specific parser -- but the script itself and the Darwin cook path
both still want a real first run before you rely on them, the same
honesty standard every other not-yet-hardware-verified piece of this
project holds itself to.
