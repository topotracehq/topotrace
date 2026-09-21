# Workspace tools, presentation, and recovery

Open **Tools** (`/#/tools`) for reports, configuration backup, and notification
controls. These additions are included in version **2026.09.18.4**.

## Presentation mode

Select **Presentation mode** in Tools or Visibility. Text and evidence tables
become larger; authentication, global search, and marked setup controls are hidden.
The demo banner stays visible while scrolling. Select **Exit presentation** or
press Escape to return to normal. The preference lasts for the browser tab's
session. Presentation mode changes display only; it does not change permissions.

## Demo scenarios

Open **Visibility → Demo showcase** and choose **Fleet overview**, **New
unauthorized device**, **Failed change**, or **Verified recovery**. The recovery
story displays the original failure next to a success verified by newer service
evidence. It uses the same verification function as live remediation but never
queues an action. The unauthorized-device scenario demonstrates an operator's
classification; it does not block network access. **Reset demo** restores the
overview. All scenario data is fictional and disposable.

## Branded reports and About

**Branded executive report** uses the current authorized fleet. **Branded demo
report** uses the isolated fictional fleet and carries a DEMO DATA banner.
Reports contain the company logo, an executive summary, key findings, recommended
next steps, and the copyright notice. The logo is embedded so saved reports work
offline. Use the report's **Print / save as PDF** button or browser print command.
Reports are evidence snapshots, not a certification or guarantee of security.

The footer's **About TopoTrace** link shows the release version, build revision,
company information, and support guidance. No support email address is invented;
contact the administrator of your deployment.

## Configuration backup and tested recovery

An unscoped administrator can export a portable JSON file containing **dynamic
groups, saved views, and notification preferences**. It intentionally excludes
inventory, policies, credentials, integration secrets, actions, accepted-risk
exceptions, and server settings. This is workspace-configuration recovery, not a
complete server/database backup. See **Full-server Recovery** for the latter.

To restore:

1. Choose the saved JSON file in Tools.
2. Select **Preview restore**. Inspect the missing records to create and existing
   records to preserve.
3. Select **Restore missing records**. Existing records are never overwritten or
   deleted. If the configuration changed after preview, preview again.
4. Check the restored groups, views, and preferences. Private views retain their
   original account name and group; that account and scope must exist to use them.

The format is `topotrace-workspace-config-v1`, limited to 1,000 records and a 4 MB
request. Export rejects data too large for this portable format. Imports reject
unknown record types and action records. The preview fingerprint binds the exact
file to the current configuration, but is not a cryptographic signature of the
file's author. Only import files from a source you trust.

An interrupted restore can leave some missing records created. Preview and retry
the same file to resume safely; already-created records are preserved. It is a
merge, not a database transaction. Tests cover export, missing-record recovery,
preservation of existing records, stale-preview rejection, scope restrictions,
and rejection of executable workflow records. Full production disaster recovery
has not been exercised automatically.

## Change safeguards

New staged service restarts require confirmation of backups and a recovery path,
plus recovery instructions of 10–4,000 characters. Document the recovery owner,
backup location, restoration steps, and verification procedure. A service restart
cannot undo disconnected sessions; these instructions are manual recovery guidance,
not an automatic rollback promise.

**Check impact & readiness** shows interruption risks and per-device blockers:
stale/missing reports, late or failing agents, missing/stale service inventory,
an absent service, outstanding actions, and overlapping scheduled changes.
Incomplete security coverage and a stopped service are warnings. The server
checks again when scheduling, and before each dispatch. A blocked dispatch shows
`preflight_blocked`; it can proceed on a later evaluation if readiness returns
within its window. Cancellation stops undelivered work only. Existing plans retain
their original behavior and are labeled legacy plans in the UI. Manual actions
and policy automation outside staged plans do not gain these new checks.

## Notification controls

Unscoped administrators can configure daily quiet hours (whole hours), an IANA
timezone such as `America/Chicago`, digest intervals, and overdue-work escalation.
Quiet hours may cross midnight; daylight-saving transitions use the timezone's
rules. The start hour is included, the end hour excluded. New events are queued
durably and delivered when quiet hours end; existing queued deliveries also wait.
An already in-flight send cannot be recalled.

A digest interval of 0 preserves immediate delivery. Otherwise choose 15–1,440
minutes. New events are grouped by destination and delivery interval, at most 100
per summary. Long event lines are truncated to 1,500 bytes. Destinations still
receive only event types they accepted before grouping; grouped delivery uses
event type `digest`. Validate downstream custom consumers before enabling it.
Delivery uses the existing retry/dead-letter queue and survives server restart.
Changing digest settings does not unpack existing digests or regroup old events.

Escalation delay is hours after an assignment's due date. Repeat interval 0 means
once per assignment revision; a positive interval repeats while the work remains
open and overdue. The assignment must name an escalation contact. The contact is
included in messages to existing destinations, not emailed directly. Quiet hours
and digest timing also apply to these notifications. Defaults remain unchanged:
no quiet hours, immediate delivery, no delay, and one escalation per revision.

Explicit test notifications and SIEM forwarding are separate paths and bypass
these controls. This feature does not add destinations or send a test message
merely because preferences are saved.

## Personal and team saved views

Visibility's history, health, and discovery sections, plus Work queue, have a
**Saved views & layout** panel. Save the current search/filter and comfortable or
compact spacing with a name. Select a saved view to restore it. Private views are
visible only to the same named account and group. Sharing requires `remediate`
access and makes the view available within the credential's group; unscoped users
share within the fleet-wide scope. Only the creator may delete a view. Each
account/group can create up to 50 views. Saved filters never expand data access.
The isolated demo does not save live views.

## API additions

| Endpoint | Access / purpose |
|---|---|
| `GET /api/about` | Public product/build information; no configuration secrets |
| `GET /api/saved-views` | Strict readonly; own and group-shared views |
| `POST /api/saved-views` | Strict readonly for personal, remediate for shared |
| `DELETE /api/saved-views/{id}` | Strict readonly; creator and same group only |
| `GET/PUT /api/notification-preferences` | Unscoped admin |
| `GET /api/config-backup` | Unscoped admin; portable JSON export |
| `POST /api/config-backup/preview` | Unscoped admin; body `{ "backup": ... }` |
| `POST /api/config-backup/restore` | Unscoped admin; backup plus `preview_hash` |
| `POST /api/change-plans/preflight` | Remediate; plan body, no queued actions |

`GET /api/visibility?demo=1&scenario=recovery` selects a sample story.
`GET /api/reports/executive?demo=1` creates the branded demo report.
