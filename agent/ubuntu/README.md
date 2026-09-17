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
  `/proc/meminfo`, `/etc/os-release`, plus the newer feeds' sources --
  `/etc/passwd`, its own crontab, `dpkg -l`, `ss -tln`) is either
  world-readable or the reporting user's own by default.

## Quick start

```bash
./muster-agent.sh --muster-host <server-ip-or-hostname>
```

Reports this machine under its own `hostname`. Run `./muster-agent.sh
--help` for every option (`--host-name` to report under a different
name, `--platform`, `--muster-port`, `--out-dir`, `--keep-files` to
inspect what was collected/sent).

## No spare Ubuntu box handy? Use the bundled Docker image

`Dockerfile` in this same directory packages the script into a plain
Ubuntu image, so you can run a real copy of it in a container against
your `muster` container instead of needing an actual second machine.
From the repo root, via Compose (see `docker-compose.yml`'s
`ubuntu-agent` service):

```bash
docker compose up -d muster
docker compose --profile ubuntu-agent run --rm ubuntu-agent
```

That's a genuine run of this same script inside its own container --
its own `/proc/cpuinfo`, `uname -a`, etc. -- not a synthetic fixture.
See the main README's "Testing with the Ubuntu/Linux agent" section for
the full walkthrough, including how to override the host name/target.

**Note:** the Dockerfile/Compose wiring was validated with `docker
compose config` but not actually built (no Docker daemon was available
in the environment this was written in). The script itself is already
proven for real, per the "Verification status" note below -- what's
unbuilt is specifically the container image.

## Running on a schedule

Two supported ways, same idea as `charts/muster/templates/
cronjob-agent.yaml` inside Kubernetes:

- **cron** — the simplest option: `crontab -e` and add
  `*/15 * * * * /opt/muster/muster-agent.sh --muster-host <host> >> /var/log/muster-agent.log 2>&1`.
- **systemd timer** — `systemd/muster-agent.service` +
  `systemd/muster-agent.timer` in this directory. Preferred on any host
  that already uses systemd: you get `systemctl status`/`journalctl`
  for free instead of a log file you have to remember to rotate. Copy
  both units to `/etc/systemd/system/`, copy `systemd/
  muster-agent.env.example` to `/etc/muster-agent.env` and fill it in,
  then:

  ```bash
  sudo useradd --system --no-create-home muster-agent
  sudo systemctl daemon-reload
  sudo systemctl enable --now muster-agent.timer
  ```

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
