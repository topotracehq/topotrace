#!/usr/bin/env bash
#
# Minimal Ubuntu/Linux agent for Muster: collects basic system facts and
# pushes them to a Muster ingest daemon over the MUSTER1 wire protocol.
#
# This is the Linux counterpart to agent/windows/muster-agent.ps1 (and,
# like it, a real one-shot collector, not a synthetic test fixture the
# way cmd/demoagent is). It shells out to the same five commands
# internal/cook/linux.go was designed around -- `cat /proc/cpuinfo`,
# `cat /proc/meminfo`, `uname -a`, `cat /etc/os-release`, `uptime` -- and
# sends their raw output, gzip-tarred, over a raw TCP socket using the
# same MUSTER1 header-plus-payload protocol cmd/demoagent and the Windows
# agent both use:
#
#     MUSTER1 <platform> <host> <payload-bytes>\n
#     <that many raw bytes of gzip-compressed tar>
#
# The capture file names/contents are Muster's own raw-capture contract
# (see internal/cook/linux.go's doc comment) -- this script just runs the
# exact commands that contract expects and tars the results, no parsing
# of its own.
#
# Requirements: bash (uses /dev/tcp, a bash built-in -- no netcat/socat
# needed), tar, gzip. All standard on any Ubuntu install; no packages to
# add.
#
# Usage:
#   ./muster-agent.sh --muster-host <host> [options]
#
# Options:
#   --muster-host HOST   Required. Hostname/IP of the Muster ingest daemon.
#   --muster-port PORT   Ingest daemon TCP port (default: 9090).
#   --host-name NAME     Name to report this host as in Muster
#                         (default: $(hostname), sanitized). Must match
#                         the server's token rules: letters, digits,
#                         '.', '_', '-' only, max 128 chars.
#   --platform NAME      Platform tag to report (default: linux). Only
#                         change this if internal/cook has a matching
#                         parser -- otherwise the server stores the host
#                         with an empty summary.
#   --out-dir DIR        Directory to write capture files + archive into
#                         (default: a fresh mktemp -d).
#   --keep-files          Don't delete --out-dir's contents afterward.
#   -h, --help            Show this help and exit.
#
# Examples:
#   ./muster-agent.sh --muster-host 192.168.1.50
#   ./muster-agent.sh --muster-host localhost --host-name webbox01 --keep-files
#
# Verification status: the wire protocol and the capture-file format this
# script produces are the same contract internal/cook/linux.go already
# parses and internal/cook/linux_test.go already covers -- that half is
# fully tested. This script itself mirrors cmd/demoagent's protocol
# handling exactly and has been reasoned through carefully, but treat a
# first run the normal way you'd treat any new script: try it against a
# test/dev Muster instance before trusting it on anything that matters.

set -euo pipefail

MUSTER_PORT=9090
HOST_NAME="$(hostname 2>/dev/null || echo unknown-host)"
PLATFORM="linux"
OUT_DIR=""
KEEP_FILES=0
MUSTER_HOST=""

usage() {
    sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --muster-host) MUSTER_HOST="$2"; shift 2 ;;
        --muster-port) MUSTER_PORT="$2"; shift 2 ;;
        --host-name) HOST_NAME="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
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

for cmd in tar gzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: '$cmd' not found on PATH -- required to package the capture files." >&2
        exit 1
    fi
done

CLEANUP_DIR=""
if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$(mktemp -d -t muster-agent.XXXXXX)"
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

# Each capture is best-effort: if a source is unreadable (permissions,
# unusual minimal install), skip that one file rather than failing the
# whole run -- internal/cook/linux.go tolerates any subset of these five
# files being absent.
collected=()

if [[ -r /proc/cpuinfo ]]; then
    cat /proc/cpuinfo > "$OUT_DIR/cpuinfo.txt"
    collected+=("cpuinfo.txt")
else
    echo "  (skipping cpuinfo.txt -- /proc/cpuinfo not readable)" >&2
fi

if [[ -r /proc/meminfo ]]; then
    cat /proc/meminfo > "$OUT_DIR/meminfo.txt"
    collected+=("meminfo.txt")
else
    echo "  (skipping meminfo.txt -- /proc/meminfo not readable)" >&2
fi

if command -v uname >/dev/null 2>&1; then
    uname -a > "$OUT_DIR/uname.txt"
    collected+=("uname.txt")
fi

if [[ -r /etc/os-release ]]; then
    cat /etc/os-release > "$OUT_DIR/os-release.txt"
    collected+=("os-release.txt")
else
    echo "  (skipping os-release.txt -- /etc/os-release not readable)" >&2
fi

if command -v uptime >/dev/null 2>&1; then
    uptime > "$OUT_DIR/uptime.txt"
    collected+=("uptime.txt")
fi

if [[ ${#collected[@]} -eq 0 ]]; then
    echo "Error: nothing could be collected -- nothing to send." >&2
    exit 1
fi

# --- package -------------------------------------------------------------
archive="$OUT_DIR/payload.tar.gz"
echo "Packaging capture files: ${collected[*]}"
# -C changes into $OUT_DIR before adding files, so the archive contains
# bare "cpuinfo.txt" etc. at its root -- matching what the server's
# extractPayload() expects (flat files, no leading directory component).
tar -czf "$archive" -C "$OUT_DIR" "${collected[@]}"

payload_size="$(wc -c < "$archive" | tr -d '[:space:]')"
echo "Packaged $payload_size bytes."

# --- send over MUSTER1 -----------------------------------------------------
echo "Connecting to ${MUSTER_HOST}:${MUSTER_PORT} ..."
exec 3<>"/dev/tcp/${MUSTER_HOST}/${MUSTER_PORT}"

printf 'MUSTER1 %s %s %s\n' "$PLATFORM" "$HOST_NAME" "$payload_size" >&3
cat "$archive" >&3

reply=""
read -r -u 3 reply || true
echo "Server replied: $reply"

exec 3<&- 3>&-

if [[ "$reply" != OK* ]]; then
    echo "Error: Muster ingest daemon did not report success: $reply" >&2
    exit 1
fi

echo "Done -- reported as platform='$PLATFORM' host='$HOST_NAME'."
