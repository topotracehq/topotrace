#!/usr/bin/env bash
################################################################################
# @file         install.sh
# @brief        Convenience installer for a standalone systemd deployment of TopoTrace.
# @project      TopoTrace
#
# @author       Michael McGinnis
# @date         2026-09-17
# @version      1.0.0
#
# Copyright (c) 2026 TopoTrace LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
################################################################################

#
# Convenience installer for a standalone systemd deployment of TopoTrace.
# Not required -- everything it does is also spelled out step-by-step in
# README.md if you'd rather run each step by hand (or adapt it for a
# config-management tool instead of a shell script). This script only
# ever creates things; it never removes or overwrites a config file that
# already exists, and it's safe to re-run after a binary upgrade.
#
# Usage:
#   sudo ./install.sh [path-to-topotrace-binary]
#
# If no path is given, it looks for ./topotrace (i.e. built via the command
# in README.md's "Build" section, run from the repo root, then this
# script run as `sudo deploy/systemd/install.sh ../../topotrace` or with
# the binary copied alongside it first).

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must be run as root (it creates a system user and installs a unit file). Try: sudo $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${1:-$SCRIPT_DIR/topotrace}"

if [ ! -f "$BIN_SRC" ]; then
  echo "No topotrace binary found at $BIN_SRC." >&2
  echo "Build one first: CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags=\"-s -w\" -o topotrace ./cmd/topotrace" >&2
  echo "Then re-run: sudo $0 /path/to/topotrace" >&2
  exit 1
fi

echo "==> Creating system user/group 'topotrace' (if not already present)"
if ! getent group topotrace >/dev/null; then
  groupadd --system topotrace
fi
if ! getent passwd topotrace >/dev/null; then
  useradd --system --gid topotrace --home-dir /var/lib/topotrace --shell /usr/sbin/nologin \
    --comment "TopoTrace inventory server" topotrace
fi

echo "==> Creating directories"
install -d -o topotrace -g topotrace -m 0750 /var/lib/topotrace
install -d -o topotrace -g topotrace -m 0750 /var/lib/topotrace/data
install -d -o root -g topotrace -m 0750 /etc/topotrace

echo "==> Installing binary to /usr/local/bin/topotrace"
install -o root -g root -m 0755 "$BIN_SRC" /usr/local/bin/topotrace

echo "==> Installing wrapper script and unit file"
install -o root -g root -m 0755 "$SCRIPT_DIR/topotrace-server.sh" /usr/local/bin/topotrace-server.sh
install -o root -g root -m 0644 "$SCRIPT_DIR/topotrace.service" /etc/systemd/system/topotrace.service

if [ ! -f /etc/topotrace/topotrace.env ]; then
  echo "==> Installing topotrace.env (no config yet -- starts with all defaults, no auth)"
  install -o root -g topotrace -m 0640 "$SCRIPT_DIR/topotrace.env.example" /etc/topotrace/topotrace.env
  echo "    Edit /etc/topotrace/topotrace.env (at minimum, set TOPOTRACE_AUTH_TOKEN) before exposing this beyond localhost."
else
  echo "==> /etc/topotrace/topotrace.env already exists, leaving it untouched"
fi

echo "==> Reloading systemd and enabling topotrace.service"
systemctl daemon-reload
systemctl enable topotrace.service

cat <<MSG

Installed. Review /etc/topotrace/topotrace.env, then:
  sudo systemctl start topotrace
  sudo systemctl status topotrace
  journalctl -u topotrace -f

The web dashboard and API will be on the address in TOPOTRACE_API_ADDR
(default :8080); the agent ingest daemon on TOPOTRACE_INGEST_ADDR (default
:9090). See README.md for firewall and reverse-proxy notes.
MSG
