#!/usr/bin/env bash
################################################################################
# @file         muster-agent.sh
# @brief        Minimal macOS agent for Muster: collects basic system facts and pushes them to a Muster ingest daemon over the MUSTER1 wire protocol.
# @project      Muster
#
# @author       Michael McGinnis
# @date         2026-09-17
# @version      1.0.0
#
# Copyright (c) 2026 TopoTrace LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
################################################################################

#
# Minimal macOS agent for Muster: collects basic system facts and pushes
# them to a Muster ingest daemon over the MUSTER1 wire protocol.
#
# Scoped deliberately smaller than the Ubuntu agent: system_summary only
# (CPU/memory/OS/kernel/uptime), not the eight newer feed categories --
# internal/cook/darwin.go doesn't parse those for this platform yet (see
# its doc comment). Extending both sides together is a natural next
# step once there's a real macOS fleet to build and test that against.
#
#     MUSTER1 <platform> <host> <token> <payload-bytes>\n
#     <that many raw bytes of gzip-compressed tar>
#
# Written for macOS's stock /bin/bash (3.2 -- Apple ships an old GPLv2
# build, not bash 4+), which is why this uses `read ... <&3` rather than
# the Linux agent's `read -u 3`: -u wasn't added to bash's read builtin
# until 4.1. Everything else here is the same protocol handling as
# agent/ubuntu/muster-agent.sh.
#
# Requirements: bash (ships with macOS; uses /dev/tcp, a bash built-in),
# tar (macOS's bsdtar), gzip. All standard on any Mac -- nothing to
# install.
#
# Usage:
#   ./muster-agent.sh --muster-host <host> [options]
#
# Options:
#   --muster-host HOST   Required. Hostname/IP of the Muster ingest daemon.
#   --muster-port PORT   Ingest daemon TCP port (default: 9090).
#   --host-name NAME     Name to report this host as (default: $(hostname),
#                         sanitized). Letters, digits, '.', '_', '-' only.
#   --platform NAME      Platform tag to report (default: darwin).
#   --token TOKEN         Shared secret matching the server's -auth-token,
#                         if it was started with one.
#   --out-dir DIR         Directory to write capture files + archive into.
#   --keep-files          Don't delete --out-dir's contents afterward.
#   -h, --help            Show this help and exit.
#
# Verification status: internal/cook/darwin.go's parser reuses the same
# generic "Key: Value" parser windows.go's tests already exercise, but
# neither this script nor that parser has been run against a real macOS
# host or a live server yet -- there's no Mac in the environment this was
# built in. Treat a first run with the normal caution any new,
# not-yet-executed script deserves.

set -euo pipefail

MUSTER_PORT=9090
HOST_NAME="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown-host)"
PLATFORM="darwin"
OUT_DIR=""
KEEP_FILES=0
MUSTER_HOST=""
TOKEN=""

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --muster-host) MUSTER_HOST="$2"; shift 2 ;;
        --muster-port) MUSTER_PORT="$2"; shift 2 ;;
        --host-name) HOST_NAME="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --keep-files) KEEP_FILES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$MUSTER_HOST" ]]; then
    echo "Error: --muster-host is required." >&2
    exit 1
fi

assert_safe_token() {
    local value="$1" name="$2"
    if [[ ${#value} -eq 0 || ${#value} -gt 128 || ! "$value" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "Error: $name '$value' is not a valid Muster token -- must be 1-128 chars of letters, digits, '.', '_', '-' only (this matches the server's own validation, so a bad token would be rejected there anyway)." >&2
        exit 1
    fi
}
assert_safe_token "$PLATFORM" "--platform"
assert_safe_token "$HOST_NAME" "--host-name"
if [[ -n "$TOKEN" ]]; then
    assert_safe_token "$TOKEN" "--token"
fi
AUTH_TOKEN="${TOKEN:--}"

for cmd in tar gzip sysctl sw_vers; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: '$cmd' not found on PATH." >&2
        exit 1
    fi
done

CLEANUP_DIR=""
if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/muster-agent.XXXXXX")"
    CLEANUP_DIR="$OUT_DIR"
else
    mkdir -p "$OUT_DIR"
fi
cleanup() {
    if [[ "$KEEP_FILES" -eq 0 && -n "$CLEANUP_DIR" && -d "$CLEANUP_DIR" ]]; then
        rm -rf "$CLEANUP_DIR"
    fi
}
trap cleanup EXIT

echo "Collecting system info into $OUT_DIR ..."

# One flat "Key: Value" file -- same format internal/cook/windows.go's
# parseWindowsKV already parses generically, reused as-is by
# internal/cook/darwin.go rather than inventing a macOS-specific format.
{
    echo "CPUBrand: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")"
    echo "NumCPUs: $(sysctl -n hw.ncpu 2>/dev/null || echo "")"
    echo "MemoryBytes: $(sysctl -n hw.memsize 2>/dev/null || echo "")"
    echo "ProductName: $(sw_vers -productName 2>/dev/null || echo "")"
    echo "ProductVersion: $(sw_vers -productVersion 2>/dev/null || echo "")"
    echo "KernelVersion: $(uname -r 2>/dev/null || echo "")"
    echo "Uptime: $(uptime 2>/dev/null || echo "")"
} > "$OUT_DIR/system.txt"

# --- browser extensions ------------------------------------------------
# Same line format as the Linux agent (see agent/ubuntu/muster-agent.sh):
# browser, user/profile, id, version, base64 manifest.json, base64
# English messages.json. macOS keeps Chromium-family profiles under
# ~/Library/Application Support.
capture_files=(system.txt)
ext_out="$OUT_DIR/browser_extensions.txt"
: > "$ext_out"
for home in /Users/*; do
    [[ -d "$home" && -r "$home" ]] || continue
    for spec in "chrome:Library/Application Support/Google/Chrome" "chromium:Library/Application Support/Chromium" "brave:Library/Application Support/BraveSoftware/Brave-Browser" "edge:Library/Application Support/Microsoft Edge"; do
        browser="${spec%%:*}"
        dir="$home/${spec#*:}"
        [[ -d "$dir" ]] || continue
        for manifest in "$dir"/*/Extensions/*/*/manifest.json; do
            [[ -f "$manifest" ]] || continue
            verdir="${manifest%/manifest.json}"
            iddir="${verdir%/*}"
            profdir="${iddir%/Extensions/*}"
            msgs=""
            for loc in en en_US en_GB; do
                if [[ -f "$verdir/_locales/$loc/messages.json" ]]; then
                    msgs="$(base64 < "$verdir/_locales/$loc/messages.json" | tr -d '\n')"
                    break
                fi
            done
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$browser" "$(basename "$home")/$(basename "$profdir")" \
                "$(basename "$iddir")" "$(basename "$verdir")" "$(base64 < "$manifest" | tr -d '\n')" "$msgs" >> "$ext_out" 2>/dev/null || true
        done
    done
done
if [[ -s "$ext_out" ]]; then
    capture_files+=(browser_extensions.txt)
else
    rm -f "$ext_out"
fi

# --- package -------------------------------------------------------------
archive="$OUT_DIR/payload.tar.gz"
echo "Packaging capture files: ${capture_files[*]}"
tar -czf "$archive" -C "$OUT_DIR" "${capture_files[@]}"

payload_size="$(wc -c < "$archive" | tr -d '[:space:]')"
echo "Packaged $payload_size bytes."

# --- send over MUSTER1 -----------------------------------------------------
echo "Connecting to ${MUSTER_HOST}:${MUSTER_PORT} ..."
exec 3<>"/dev/tcp/${MUSTER_HOST}/${MUSTER_PORT}"

printf 'MUSTER1 %s %s %s %s\n' "$PLATFORM" "$HOST_NAME" "$AUTH_TOKEN" "$payload_size" >&3
cat "$archive" >&3

# macOS's stock bash is 3.2 (Apple stays on the last GPLv2 release) --
# `read -u FD` wasn't added until bash 4.1, so this redirects fd 3 onto
# read's stdin instead, which has worked since bash 2.x.
reply=""
read -r reply <&3 || true
echo "Server replied: $reply"

exec 3<&- 3>&-

if [[ "$reply" != OK* ]]; then
    echo "Error: Muster ingest daemon did not report success: $reply" >&2
    exit 1
fi

echo "Done -- reported as platform='$PLATFORM' host='$HOST_NAME'."
