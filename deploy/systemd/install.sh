#!/usr/bin/env bash
#
# Convenience installer for a standalone systemd deployment of Muster.
# Not required -- everything it does is also spelled out step-by-step in
# README.md if you'd rather run each step by hand (or adapt it for a
# config-management tool instead of a shell script). This script only
# ever creates things; it never removes or overwrites a config file that
# already exists, and it's safe to re-run after a binary upgrade.
#
# Usage:
#   sudo ./install.sh [path-to-muster-binary]
#
# If no path is given, it looks for ./muster (i.e. built via the command
# in README.md's "Build" section, run from the repo root, then this
# script run as `sudo deploy/systemd/install.sh ../../muster` or with
# the binary copied alongside it first).

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must be run as root (it creates a system user and installs a unit file). Try: sudo $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${1:-$SCRIPT_DIR/muster}"

if [ ! -f "$BIN_SRC" ]; then
  echo "No muster binary found at $BIN_SRC." >&2
  echo "Build one first: CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags=\"-s -w\" -o muster ./cmd/muster" >&2
  echo "Then re-run: sudo $0 /path/to/muster" >&2
  exit 1
fi

echo "==> Creating system user/group 'muster' (if not already present)"
if ! getent group muster >/dev/null; then
  groupadd --system muster
fi
if ! getent passwd muster >/dev/null; then
  useradd --system --gid muster --home-dir /var/lib/muster --shell /usr/sbin/nologin \
    --comment "Muster inventory server" muster
fi

echo "==> Creating directories"
install -d -o muster -g muster -m 0750 /var/lib/muster
install -d -o muster -g muster -m 0750 /var/lib/muster/data
install -d -o root -g muster -m 0750 /etc/muster

echo "==> Installing binary to /usr/local/bin/muster"
install -o root -g root -m 0755 "$BIN_SRC" /usr/local/bin/muster

echo "==> Installing wrapper script and unit file"
install -o root -g root -m 0755 "$SCRIPT_DIR/muster-server.sh" /usr/local/bin/muster-server.sh
install -o root -g root -m 0644 "$SCRIPT_DIR/muster.service" /etc/systemd/system/muster.service

if [ ! -f /etc/muster/muster.env ]; then
  echo "==> Installing muster.env (no config yet -- starts with all defaults, no auth)"
  install -o root -g muster -m 0640 "$SCRIPT_DIR/muster.env.example" /etc/muster/muster.env
  echo "    Edit /etc/muster/muster.env (at minimum, set MUSTER_AUTH_TOKEN) before exposing this beyond localhost."
else
  echo "==> /etc/muster/muster.env already exists, leaving it untouched"
fi

echo "==> Reloading systemd and enabling muster.service"
systemctl daemon-reload
systemctl enable muster.service

cat <<MSG

Installed. Review /etc/muster/muster.env, then:
  sudo systemctl start muster
  sudo systemctl status muster
  journalctl -u muster -f

The web dashboard and API will be on the address in MUSTER_API_ADDR
(default :8080); the agent ingest daemon on MUSTER_INGEST_ADDR (default
:9090). See README.md for firewall and reverse-proxy notes.
MSG
