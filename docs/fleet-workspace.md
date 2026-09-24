# Fleet workspace

The workspace connects evidence, investigation, and reporting. Use **Today** for
the current operational picture, then follow a metric or workflow into the
underlying evidence. Existing Hosts, Work queue, Visibility, and demonstration
scenarios remain available.

## Today and inbox

Today summarizes managed devices, reporting gaps, open findings, and new
discoveries. It shows the five most recent attention items and four common paths:
search evidence, compare devices, review discoveries, and build a report. This is
an entry point rather than a second navigation system; the permanent sidebar
remains the source of truth for product areas.

The inbox combines current findings, stale agent reports, newly discovered
devices, and failed or uncertain deployment jobs. Read/unread state is stored per
authenticated account and group. API keys shared by multiple people also share
that state. Resolved conditions leave this current-state inbox; it is not a
permanent event archive.

## Search, collections and comparison

Search matches host metadata, reported fact content (including reported IP addresses and software), current finding text, and documentation. Results respect the caller's host scope and return at most 100 matches. Searches require at least two characters.

Collections save explicit device membership for later reference and report selection. They do not automatically grow when new devices arrive; use existing dynamic groups for rule-based membership. Remediate permission is required to create or delete collections. Scoped users see only collections in their scope and hosts still visible to them.

Compare chooses a reference device and a second device, then shows differing reported fields. Package and service collections remain grouped by their evidence field. The reference is its current evidence, not a frozen historical baseline. Missing fields mean unknown, and timestamps may differ. Open either host's detail to inspect original evidence.

## Integration health and onboarding

Integration health requires an unscoped administrator. It shows notification destinations, pending attempts, failed deliveries, and the last successful delivery observed since this release. A configured SIEM or vulnerability feed is not a claim of successful delivery or current connectivity; those integrations currently expose configuration status only.

Getting started guides enrollment, a fresh report, policy review, and investigation of a first finding. Completion indicators are inferred from current evidence; they do not certify that every device is configured correctly. Use the existing labeled demo showcase to practice without changing live inventory.

## Report builder

Select a collection, optional board group, UTC date range, executive or technical presentation, and sections. All reports include a branded summary. Executive reports show the ten highest-risk selected hosts; technical reports show all selected hosts. Optional sections include hosts, vulnerabilities, retained trend and recent activity. Activity remains restricted to administrators.

Inventory is a snapshot at report generation time. Date selection filters retained history and activity, not the current inventory into a historical assessment. Trend aggregation remains limited to the most recent 30 days; activity comes from the latest 200 audit records, with up to 15 shown. Print the generated HTML to PDF using the browser.

New collections, inbox state, delivery health and site operations use the existing document store. They require full-server backups and are not included in the limited workspace configuration export.

## Fleet and work queue

Fleet keeps health, risk, and pending approvals in one scan-friendly view. Work
queue separates Findings, Ownership, Dynamic groups, and Change plans, then keeps
filters close to the finding list.

## API

- `GET /api/overview`: scoped attention list and counts.
- `GET /api/search-all?q=...`: scoped global search.
- `GET/POST /api/collections`, `DELETE /api/collections/{id}`.
- `GET /api/compare?a=host-one&b=host-two`.
- `PUT /api/inbox/{id}` with `{"read":true}` or `{"read":false}`.
- `GET /api/integration-health` for unscoped admins.
- `GET /api/reports/executive` accepts `collection`, `group`, `from`, `to`, `mode=executive|technical`, and comma-separated `sections=hosts,vulnerabilities,trend,activity`.

See [Discovery & remote deployment](site-operations.md) for workers and staged installation.
