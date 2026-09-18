#!/usr/bin/env bash
################################################################################
# @file         muster-agent.sh
# @brief        Minimal Ubuntu/Linux agent for Muster: collects basic system facts and pushes them to a Muster ingest daemon over the MUSTER1 wire protocol.
# @project      Muster
#
# @author       Michael McGinnis
# @date         2026-09-14
# @version      1.0.0
#
# Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
# Licensed under the MIT License -- see the LICENSE file at the repository root.
################################################################################

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
#     MUSTER1 <platform> <host> <token> <payload-bytes>\n
#     <that many raw bytes of gzip-compressed tar>
#
# If the server hands back a second reply line -- a queued remediation
# action (`ACTION <id> <verb> <arg>`) -- this script executes it if (and
# only if) the verb is one of the small set case-matched in run_action
# below, then reports the outcome back over a second, short
# MUSTER1-RESULT connection. See internal/remediate/actions.go for the
# authoritative allow-list; an unknown or not-yet-implemented verb is
# reported "unsupported," never guessed at or passed to a shell as-is.
#
# The capture file names/contents are Muster's own raw-capture contract
# (see internal/cook/linux.go's doc comment) -- this script just runs the
# exact commands that contract expects and tars the results, no parsing
# of its own. Beyond those original five, it also captures df -Pk,
# dpkg -l, running systemd units, listening TCP sockets (ss -tln),
# /etc/passwd, network interfaces (ip -o addr), the reporting user's own
# crontab, apt's upgradable-package list, and ufw's status -- each fully
# best-effort (see internal/cook/linux_extra.go for what's parsed from
# each, and what's tolerated as absent).
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
#   --token TOKEN         Shared secret matching the server's -auth-token,
#                         if it was started with one. Omit if the server
#                         has no -auth-token configured. Same charset as
#                         --host-name applies.
#   --out-dir DIR         Directory to write capture files + archive into
#                         (default: a fresh mktemp -d).
#   --keep-files          Don't delete --out-dir's contents afterward.
#   -h, --help            Show this help and exit.
#
# Examples:
#   ./muster-agent.sh --muster-host 192.168.1.50
#   ./muster-agent.sh --muster-host localhost --host-name webbox01 --keep-files
#   ./muster-agent.sh --muster-host 192.168.1.50 --token "$MUSTER_TOKEN"
#
# Verification status: the wire protocol and the capture-file format this
# script produces are the same contract internal/cook/linux.go already
# parses and internal/cook/linux_test.go already covers -- that half is
# fully tested. This script itself mirrors cmd/demoagent's protocol
# handling exactly and has been reasoned through carefully, but treat a
# first run the normal way you'd treat any new script: try it against a
# test/dev Muster instance before trusting it on anything that matters.
# The remediation path (run_action/report_action_result below) is new
# and has not been exercised against a live server with a real queued
# action -- try --token plus a manually-queued restart-service action
# against a throwaway service before relying on it.

set -euo pipefail

MUSTER_PORT=9090
HOST_NAME="$(hostname 2>/dev/null || echo unknown-host)"
PLATFORM="linux"
OUT_DIR=""
KEEP_FILES=0
MUSTER_HOST=""
TOKEN=""
AIRGAP_OUT=""

usage() {
    sed -n '2,58p' "$0" | sed 's/^# \{0,1\}//'
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
        --airgap-out) AIRGAP_OUT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$MUSTER_HOST" && -z "$AIRGAP_OUT" ]]; then
    echo "Error: --muster-host is required (or --airgap-out, for a host with no network route to Muster at all -- see agent/airgap/README.md)." >&2
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

# report_action_result opens a short second MUSTER1-RESULT connection to
# tell the server what happened when this script executed a delivered
# action. Best-effort: a failure to report back doesn't change the exit
# status of the run that already succeeded at its actual job (submitting
# this host's report).
report_action_result() {
    local action_id="$1" status="$2" detail="$3"
    local detail_bytes
    detail_bytes="$(printf '%s' "$detail" | wc -c | tr -d '[:space:]')"

    local rfd
    if ! exec {rfd}<>"/dev/tcp/${MUSTER_HOST}/${MUSTER_PORT}"; then
        echo "  (could not open a second connection to report the action result)" >&2
        return
    fi
    printf 'MUSTER1-RESULT %s %s %s %s\n' "$AUTH_TOKEN" "$action_id" "$status" "$detail_bytes" >&"$rfd"
    printf '%s' "$detail" >&"$rfd"
    local result_reply=""
    read -r -u "$rfd" result_reply || true
    exec {rfd}<&- {rfd}>&- 2>/dev/null || true
    echo "  Result report acknowledged: $result_reply"
}

# run_action executes an allow-listed remediation action the server
# handed back after accepting this run's report. Only the verbs
# explicitly case-matched below ever run anything -- an unknown or
# not-yet-implemented verb (see internal/remediate/actions.go) is
# reported as unsupported, never guessed at or passed to a shell as-is.
run_action() {
    local line="$1"
    local _tag action_id verb arg
    read -r _tag action_id verb arg <<< "$line"

    echo "Received action: id=$action_id verb=$verb arg=$arg"

    local status detail logfile
    logfile="$(mktemp -t muster-action.XXXXXX)"
    case "$verb" in
        restart-service)
            if systemctl restart -- "$arg" >"$logfile" 2>&1; then
                status="ok"
                detail="restarted $arg via systemctl"
            else
                status="fail"
                detail="systemctl restart $arg failed: $(tail -c 400 "$logfile")"
            fi
            ;;
        apply-updates)
            status="fail"
            detail="apply-updates is allow-listed but not yet implemented by this agent"
            ;;
        *)
            status="fail"
            detail="unsupported action verb: $verb"
            ;;
    esac
    rm -f "$logfile"

    echo "Action result: $status -- $detail"
    report_action_result "$action_id" "$status" "$detail"
}

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

# --- extra feeds: each is fully best-effort, same "skip what's missing"
# policy as the five files above. internal/cook/linux_extra.go tolerates
# any subset of these being absent.
if command -v df >/dev/null 2>&1; then
    df -Pk > "$OUT_DIR/df.txt"
    collected+=("df.txt")
fi

if command -v dpkg >/dev/null 2>&1; then
    dpkg -l > "$OUT_DIR/packages.txt" 2>/dev/null || true
    collected+=("packages.txt")
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --state=running --no-legend --no-pager > "$OUT_DIR/services.txt" 2>/dev/null || true
    collected+=("services.txt")
fi

if command -v ss >/dev/null 2>&1; then
    ss -tln > "$OUT_DIR/ports.txt" 2>/dev/null || true
    collected+=("ports.txt")
fi

if [[ -r /etc/passwd ]]; then
    cat /etc/passwd > "$OUT_DIR/users.txt"
    collected+=("users.txt")
fi

if command -v ip >/dev/null 2>&1; then
    ip -o addr show > "$OUT_DIR/interfaces.txt" 2>/dev/null || true
    collected+=("interfaces.txt")
fi

if command -v crontab >/dev/null 2>&1; then
    crontab -l > "$OUT_DIR/cron.txt" 2>&1 || true
    collected+=("cron.txt")
fi

if command -v apt >/dev/null 2>&1; then
    apt list --upgradable > "$OUT_DIR/updates.txt" 2>/dev/null || true
    collected+=("updates.txt")
fi

if command -v ufw >/dev/null 2>&1; then
    ufw status > "$OUT_DIR/firewall.txt" 2>/dev/null || true
    collected+=("firewall.txt")
fi

# --- browser extensions ------------------------------------------------
# Every Chromium-family browser profile under every local home dir:
# Chrome, Chromium, Brave, Edge all keep installed extensions at
# <profile>/Extensions/<id>/<version>/manifest.json. Each line of
# browser_extensions.txt is browser, user/profile, id, version, then the
# manifest.json and (if present) the English _locales messages.json,
# both base64 so the server parses real JSON instead of this script
# guessing at it with grep. Read-only, best-effort: a permission-denied
# home dir is skipped, and no extension means no file at all.
ext_out="$OUT_DIR/browser_extensions.txt"
: > "$ext_out"
for home in /home/* /root; do
    [[ -d "$home" && -r "$home" ]] || continue
    for spec in "chrome:.config/google-chrome" "chromium:.config/chromium" "brave:.config/BraveSoftware/Brave-Browser" "edge:.config/microsoft-edge"; do
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
    collected+=("browser_extensions.txt")
else
    rm -f "$ext_out"
fi

# --- TLS certificates ----------------------------------------------------
# Server certificates in the places they usually live (Let's Encrypt,
# nginx/apache/haproxy config dirs, the RHEL and Debian private cert
# dirs) -- not the CA bundle in /etc/ssl/certs, which is hundreds of
# roots nobody needs an expiry alert for. One tab-separated line per
# cert: path, subject, issuer, notAfter (ISO 8601 UTC). Needs openssl;
# skipped silently without it.
if command -v openssl >/dev/null 2>&1; then
    cert_out="$OUT_DIR/certs.txt"
    : > "$cert_out"
    while IFS= read -r certfile; do
        [[ -r "$certfile" ]] || continue
        enddate="$(openssl x509 -in "$certfile" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')" || continue
        [[ -n "$enddate" ]] || continue
        iso="$(date -u -d "$enddate" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$enddate")"
        subject="$(openssl x509 -in "$certfile" -noout -subject 2>/dev/null | sed 's/^subject=//')"
        issuer="$(openssl x509 -in "$certfile" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
        printf '%s\t%s\t%s\t%s\n' "$certfile" "$subject" "$issuer" "$iso" >> "$cert_out"
    done < <(find /etc/letsencrypt/live /etc/nginx /etc/apache2 /etc/httpd /etc/haproxy /etc/pki/tls/certs /etc/ssl/private /etc/ssl/local \
                -maxdepth 4 -type f \( -name '*.crt' -o -name '*.pem' -o -name 'cert*.pem' -o -name 'fullchain.pem' \) 2>/dev/null | grep -v -e '/privkey' -e '/chain.pem' | sort -u | head -200)
    if [[ -s "$cert_out" ]]; then
        collected+=("certs.txt")
    else
        rm -f "$cert_out"
    fi
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

# --- air-gapped output (no network path to Muster at all) ----------------
# Same capture + tar.gz packaging as the normal path above; instead of
# opening a socket, base64-encode the archive and write it (or print it)
# as the JSON body POST /api/airgap-report expects. See
# agent/airgap/README.md for the intended workflow: run this on the
# air-gapped host, move the resulting file by hand (USB drive, pasted
# text, a small QR code for short captures) to any machine that *can*
# reach Muster, and POST it from there.
if [[ -n "$AIRGAP_OUT" ]]; then
    echo "Air-gapped mode: encoding the payload instead of sending it over the network."
    payload_b64="$(base64 -w0 "$archive")"
    json="{\"platform\":\"$PLATFORM\",\"host\":\"$HOST_NAME\",\"payload_b64\":\"$payload_b64\"}"
    if [[ "$AIRGAP_OUT" == "-" ]]; then
        printf '%s\n' "$json"
    else
        printf '%s\n' "$json" > "$AIRGAP_OUT"
        echo "Wrote air-gapped report to $AIRGAP_OUT ($(wc -c < "$AIRGAP_OUT" | tr -d '[:space:]') bytes)."
        echo "Move this file to any machine that can reach Muster and POST it, e.g.:"
        echo "  curl -sS -X POST 'http://<muster-host>:8080/api/airgap-report' -H 'Content-Type: application/json' --data @$AIRGAP_OUT"
    fi
    if [[ "$KEEP_FILES" -eq 0 ]]; then
        rm -rf "$OUT_DIR"
    fi
    exit 0
fi

# --- send over MUSTER1 -----------------------------------------------------
echo "Connecting to ${MUSTER_HOST}:${MUSTER_PORT} ..."
exec 3<>"/dev/tcp/${MUSTER_HOST}/${MUSTER_PORT}"

printf 'MUSTER1 %s %s %s %s\n' "$PLATFORM" "$HOST_NAME" "$AUTH_TOKEN" "$payload_size" >&3
cat "$archive" >&3

reply=""
read -r -u 3 reply || true
echo "Server replied: $reply"

# The server may follow "OK <n>" with one more line delivering a queued
# remediation action for this host -- read opportunistically; if there
# isn't one, the connection is already at EOF and this just comes back
# empty.
action_line=""
read -r -u 3 action_line || true

exec 3<&- 3>&-

if [[ "$reply" != OK* ]]; then
    echo "Error: Muster ingest daemon did not report success: $reply" >&2
    exit 1
fi

echo "Done -- reported as platform='$PLATFORM' host='$HOST_NAME'."

if [[ "$action_line" == ACTION* ]]; then
    run_action "$action_line"
fi
