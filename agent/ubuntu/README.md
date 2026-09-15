# Muster Ubuntu / Linux agent

A minimal, dependency-free bash agent that scans a Linux host and reports
it to a running Muster server. See `muster-agent.sh`'s own header
comment (`./muster-agent.sh --help` prints it) for the full option list
and design notes -- this file is a short pointer, not a duplicate.

## Requirements

- bash (uses `/dev/tcp`, a bash built-in -- no netcat/socat needed).
- `tar` and `gzip` on PATH. Standard on any Ubuntu install.
- Network access from this host to the Muster server's ingest port
  (`9090` by default).
- No root/sudo needed -- everything it reads (`/proc/cpuinfo`,
  `/proc/meminfo`, `/etc/os-release`) is world-readable by default.

## Quick start

```bash
./muster-agent.sh --muster-host <server-ip-or-hostname>
```

Reports this machine under its own `hostname`. Run `./muster-agent.sh
--help` for every option (`--host-name` to report under a different
name, `--platform`, `--muster-port`, `--out-dir`, `--keep-files` to
inspect what was collected/sent).

## What it collects

The same five raw command outputs `internal/cook/linux.go` was designed
around: `/proc/cpuinfo`, `/proc/meminfo`, `uname -a`, `/etc/os-release`,
and `uptime`. No parsing on the agent side -- it just captures the raw
text and lets the server-side cook pipeline do the parsing, same as
every other Muster agent.

## Verification status

Unlike the Windows agent, this one **has** been run and verified for
real in the environment it was built in (a genuine Linux sandbox) --
end to end against a live Muster server: real `/proc/cpuinfo`/
`/proc/meminfo`/`uname -a`/`/etc/os-release`/`uptime` output was
collected, packaged, sent over the wire, and confirmed via the API to
have parsed into accurate CPU/memory/kernel/distribution facts. Still
worth a first run against a test/dev Muster instance on your own
machines before relying on it, as with any new script -- but this one
isn't a "written but untested" caveat the way the Windows script is.
