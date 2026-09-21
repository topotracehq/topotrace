# Full-server recovery

Tools' portable configuration export covers dynamic groups, saved views, and
notification preferences. Complete recovery additionally requires the server's
data, database, credentials, environment configuration, and binary. Store full
backups with restricted access: they may contain credentials and private inventory.

## Capture a recoverable deployment

1. Record the installed version from About, the service unit and overrides, the
   startup command, storage backend, data directory, and external database name.
   Use your deployed paths; the bundled systemd defaults are `/etc/topotrace` and
   `/var/lib/topotrace/data`.
2. Schedule a maintenance interval and stop TopoTrace before copying a memstore
   snapshot. Copy the **entire data directory**, including `topotrace.json`, raw
   packets, and `settings-overrides.json`, preserving ownership and permissions.
   Keep the deployed binary, service launcher/unit, environment files, and TLS
   configuration with the backup. Do not print environment secrets in a ticket.
3. For PostgreSQL, use your database backup procedure in addition to the data and
   settings files. A filesystem copy of a running database is not a substitute for
   a database-consistent backup. Record the database version and restore procedure.
4. Record hashes of the backup files, keep an off-server copy, and restart TopoTrace.
   Verify `/healthz` and a known host before closing the maintenance interval.

## Restore without overwriting the only working copy

1. Provision an isolated recovery environment using the recorded binary version.
   Keep agent ingress and outbound integrations disconnected while validating;
   restored queues, scheduled changes, and evaluator rules may otherwise resume.
2. Restore files into a **new directory**, preserving the originals and access
   permissions. Restore PostgreSQL into a separate database using the recorded
   database procedure. Point the recovery service at those restored locations.
3. Check health, login, host and rule counts, known host facts, groups, assignments,
   saved views, notification preferences, and representative audit/history records.
   Inspect pending actions, scheduled plans, notification queues, and integrations
   before permitting agents or outbound delivery.
4. Decide which pending operations are still valid, cancel obsolete undelivered
   work, and reconcile any commands whose execution status is uncertain. Do not
   replay a command just because a restored snapshot predates its result.
5. Switch service routing only after validation. Keep the previous environment
   available until the recovered service has been observed working normally.

The portable workspace restore path has automated round-trip and permission
tests. A complete PostgreSQL or production-host recovery requires an operator-led
rehearsal in your environment; this update does not claim that rehearsal occurred.
