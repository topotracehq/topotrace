#!/usr/bin/env bash
#
# Systemd's ExecStart target for muster.service. Exists as a real script
# rather than a bare ExecStart=/usr/local/bin/muster line because several
# of cmd/muster's flags have no MUSTER_*-env-var equivalent of their own
# (-ingest-addr, -api-addr, -data-dir, -evaluator-interval, -vuln-feed,
# -vuln-feed-interval -- see cmd/muster/main.go's flag list), so
# something has to turn "one env file to edit" into "the flags the
# binary actually understands." Written this way instead of relying on
# systemd's own ExecStart variable-substitution (supported since systemd
# 246) so the unit works unmodified on older systemd too.
#
# -postgres-dsn, -auth-token, and -webhook-url are deliberately NOT set
# here -- cmd/muster's own flag.String() calls already default those
# three from MUSTER_POSTGRES_DSN/MUSTER_AUTH_TOKEN/MUSTER_WEBHOOK_URLS
# via os.Getenv at flag-definition time, and systemd's EnvironmentFile=
# already exports whatever muster.env sets into this process's
# environment before exec -- so they reach the binary with zero extra
# plumbing here. Setting them again on the command line would just be a
# second, redundant place for the same value to drift out of sync.

set -euo pipefail

BIN="${MUSTER_BIN:-/usr/local/bin/muster}"

exec "$BIN" \
  -ingest-addr="${MUSTER_INGEST_ADDR:-:9090}" \
  -api-addr="${MUSTER_API_ADDR:-:8080}" \
  -data-dir="${MUSTER_DATA_DIR:-/var/lib/muster/data}" \
  -evaluator-interval="${MUSTER_EVALUATOR_INTERVAL:-5m}" \
  -vuln-feed-interval="${MUSTER_VULN_FEED_INTERVAL:-6h}" \
  ${MUSTER_VULN_FEED:+-vuln-feed}
