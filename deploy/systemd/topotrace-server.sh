#!/usr/bin/env bash
################################################################################
# @file         topotrace-server.sh
# @brief        Systemd's ExecStart target for topotrace.service.
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
# Systemd's ExecStart target for topotrace.service. Exists as a real script
# rather than a bare ExecStart=/usr/local/bin/topotrace line because several
# of cmd/topotrace's flags have no TOPOTRACE_*-env-var equivalent of their own
# (-ingest-addr, -api-addr, -data-dir, -evaluator-interval, -vuln-feed,
# -vuln-feed-interval -- see cmd/topotrace/main.go's flag list), so
# something has to turn "one env file to edit" into "the flags the
# binary actually understands." Written this way instead of relying on
# systemd's own ExecStart variable-substitution (supported since systemd
# 246) so the unit works unmodified on older systemd too.
#
# -postgres-dsn, -auth-token, and -webhook-url are deliberately NOT set
# here -- cmd/topotrace's own flag.String() calls already default those
# three from TOPOTRACE_POSTGRES_DSN/TOPOTRACE_AUTH_TOKEN/TOPOTRACE_WEBHOOK_URLS
# via os.Getenv at flag-definition time, and systemd's EnvironmentFile=
# already exports whatever topotrace.env sets into this process's
# environment before exec -- so they reach the binary with zero extra
# plumbing here. Setting them again on the command line would just be a
# second, redundant place for the same value to drift out of sync.

set -euo pipefail

BIN="${TOPOTRACE_BIN:-/usr/local/bin/topotrace}"

exec "$BIN" \
  -ingest-addr="${TOPOTRACE_INGEST_ADDR:-:9090}" \
  -api-addr="${TOPOTRACE_API_ADDR:-:8080}" \
  -data-dir="${TOPOTRACE_DATA_DIR:-/var/lib/topotrace/data}" \
  -evaluator-interval="${TOPOTRACE_EVALUATOR_INTERVAL:-5m}" \
  -vuln-feed-interval="${TOPOTRACE_VULN_FEED_INTERVAL:-6h}" \
  ${TOPOTRACE_VULN_FEED:+-vuln-feed}
