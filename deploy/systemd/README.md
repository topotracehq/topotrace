# Standalone systemd deployment

Runs Muster as a systemd service directly on a Linux VM or bare-metal
box -- the non-Kubernetes counterpart to `charts/muster` (that Helm
chart's README covers the k8s path; use whichever fits your
environment, they're independent, not a migration from one to the
other). Good fit for a home lab, a single small-business server, or
anywhere standing up a cluster just to run one inventory server isn't
worth it.

This mirrors the same systemd-service pattern the Ubuntu agent
(`agent/ubuntu/README.md`, if present, or its script's own header
comment) already assumes for itself -- one unit, one env file, `journalctl`
for logs, nothing exotic.

## Requirements

- A Linux box with systemd (Ubuntu 20.04+, Debian 11+, RHEL/Rocky 8+,
  or similar -- anything with a systemd new enough for `Restart=`/
  `ProtectSystem=strict`, which is all of the last decade's mainstream
  distros).
- Go 1.24+ to build the binary (on the box itself, or cross-compiled
  elsewhere and copied over -- `GOOS=linux GOARCH=amd64` or `arm64` as
  needed, `CGO_ENABLED=0` either way since the binary is static).
- Optionally, a Postgres instance if you want the Postgres-backed store
  instead of the default JSON-snapshot one (see `muster.env.example`).
  Not required to get started.

## Build

From the repo root, on the target box (or cross-compiled and copied
over):

```sh
CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o muster ./cmd/muster
```

Same build the `Dockerfile` uses, just not containerized -- static,
`vendor/`-only, no network access needed for the build itself since
dependencies are already vendored into the repo.

## Install

```sh
sudo deploy/systemd/install.sh ./muster
```

This creates a `muster` system user, `/var/lib/muster` (data directory)
and `/etc/muster` (config), installs the binary to
`/usr/local/bin/muster`, the wrapper script and unit file, drops a
starter `/etc/muster/muster.env` (only if one doesn't already exist),
and enables the service. It does not start it -- review the env file
first. See `install.sh`'s own comments if you'd rather run the
equivalent steps by hand or through a config-management tool instead.

## Configure

Edit `/etc/muster/muster.env` -- every setting is documented inline in
`muster.env.example`. At minimum, before exposing this past localhost or
a fully trusted LAN, set `MUSTER_AUTH_TOKEN` to a long random string;
with it unset, both the TCP ingest daemon and every API write are
unauthenticated (fine for a five-minute local eval, not for anything
else -- see the top-level README's "Authentication, roles & remediation"
section for what that token unlocks: it always resolves to the "admin"
role, from which you can mint narrower-scoped API keys via `POST
/api/keys`).

## Start

```sh
sudo systemctl start muster
sudo systemctl status muster
journalctl -u muster -f
```

`systemctl enable` (already run by `install.sh`) means it also comes
back up automatically after a reboot.

## Firewall / exposure

Two ports, both configurable in `muster.env`:

- `MUSTER_API_ADDR` (default `:8080`) -- the HTTP API and web dashboard.
  Anything that needs to browse hosts, mint enrollments, or hit `POST
  /api/mobile-report` (the Android app, the iOS Shortcuts flow) needs to
  reach this one.
- `MUSTER_INGEST_ADDR` (default `:9090`) -- the raw TCP ingest daemon the
  Linux/macOS/Windows agent scripts (`agent/ubuntu`, `agent/macos`,
  `agent/windows`) connect to. Only those agents need to reach this
  port, never a browser or a mobile device.

Neither port serves TLS on its own -- if this box is reachable outside a
trusted LAN/VPN, put a reverse proxy (Caddy, nginx, Traefik) in front of
`MUSTER_API_ADDR` for HTTPS, the same way you would for any other
internal HTTP service. The TCP ingest port has no such wrapping
available (it isn't HTTP) -- keep it on a trusted network/VPN, or point
agents at it through an SSH tunnel or a VPN overlay (Tailscale, etc.) if
they're off-LAN.

## Upgrading

Build a new binary, then:

```sh
sudo systemctl stop muster
sudo install -o root -g root -m 0755 muster /usr/local/bin/muster
sudo systemctl start muster
```

`install.sh` is safe to re-run too (it won't touch an existing
`muster.env`, and re-creating the user/directories/unit file is a
no-op if they're already there) if you'd rather script the whole
upgrade through it.

## Uninstalling

```sh
sudo systemctl disable --now muster
sudo rm /etc/systemd/system/muster.service /usr/local/bin/muster /usr/local/bin/muster-server.sh
sudo systemctl daemon-reload
# Data and config are left in place on purpose -- remove by hand if you
# actually want them gone:
# sudo rm -rf /var/lib/muster /etc/muster
# sudo userdel muster && sudo groupdel muster
```

## Unverified

`install.sh` and `muster.service` were written and reviewed by hand
(balanced quoting/braces checked, `systemd-analyze verify` was not run)
in an environment with no systemd instance and no real Linux VM to
install onto -- please run through this once on an actual box and treat
anything that doesn't match this doc as this doc being wrong, not you.
`systemd-analyze verify muster.service` after copying it into place is a
good first check if the service fails to start with no obvious error in
`journalctl`.
