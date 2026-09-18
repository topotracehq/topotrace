# Work queue and governed changes

Open **Work queue** in the dashboard. This release adds eight operator workflows:

1. **Evidence coverage.** Host posture responses include `coverage`: a percentage and four evidence rows for operating system, software inventory, firewall status, and pending updates. `verified` means usable evidence no more than 24 hours old, not a passing security check. Missing, malformed, unsupported, or undated evidence is `unknown`; older evidence is `outdated`. Each category uses its own timestamp. Windows installed hotfixes do not establish pending-update status. A perfect posture score can have incomplete coverage.
2. **Ranked work queue.** `GET /api/work` combines open policy/software alerts, vulnerability findings, posture findings, and coverage gaps. Active work sorts ahead of accepted exceptions, then by overdue status and host risk. Recommendations describe next steps; they do not execute changes. Policy alerts reflect the latest evaluator cycle; computed findings reflect current stored facts.
3. **Ownership.** Assign a finding or set default device ownership, with owner, team, due date, and escalation contact. A finding assignment overrides the device default. The evaluator records overdue open work once per assignment revision and emits `work_overdue` to configured notification sinks. The contact is included in the event, not directly emailed or messaged. Updating the assignment resets escalation tracking.
4. **Remediation verification.** Host pages distinguish requested, delivered, executed, verified, failed, timed-out, and unverifiable actions. Service restarts verify only when a fresh service report, collected after the execution result, says that service is running. The view evaluates current evidence; it is not proof that an unrelated vulnerability or policy violation was fixed. No report/result within 24 hours is timed out.
5. **Dynamic groups.** Create selectors using platform, a software-name substring, an exact tag, exposure, and minimum host risk. Conditions combine with AND; software evidence must be fresh. Fleet policy creation offers these groups by name. Membership is evaluated each cycle; existing manual board groups are unchanged. Dynamic targets apply to posture policies, not software allow/deny rules.
6. **Maintenance windows and staged changes.** Schedule service restarts for 1–100 devices, choosing a pilot count and a window up to 24 hours. Host selection is frozen at creation. The evaluator queues the pilot during the window. Agent delivery also checks the window. Promote the remaining devices explicitly after all pilots verify. Cancelling stops undelivered work only. The window applies to this plan, not unrelated manually or automatically queued actions. Package updates remain unsupported. A window can close before the agent checks in; that action will not be sent. Dispatch interrupted between queue and persistence is held for inspection rather than retried automatically.
7. **Expiring exceptions.** Admins can accept individual findings with a reason and an expiry within 90 days. Accepted findings remain visible. Exceptions for policy or software alerts suppress further evaluator notifications/remediation while active; approval is blocked until revoked. Exceptions do not recall already queued actions or change risk scores. Other finding exceptions affect work-queue triage only. At expiry, active work returns automatically; policy notifications resume on the next evaluator cycle.
8. **Evidence-linked AI answers.** Ask Muster receives numbered sources with host, category, timestamp, freshness, and a bounded source excerpt. It is instructed to cite `[E1]`-style IDs and acknowledge unknown evidence. The UI links only supplied IDs and flags missing/invalid citations. A valid source ID does not establish that the model's claim is correct. Group-scoped keys receive only their hosts' AI context.

## Permissions and storage

Reads require the normal read role; assignments and scheduled changes require authenticated `remediate` access. Exceptions and group changes require `admin`; dynamic group changes require an unscoped admin. Host access is checked for workflow writes. Records use the existing document store, so both JSON storage and PostgreSQL persist them without a schema migration. Workflow transitions are serialized within one server process: run one active Muster server against a store. Multiple active dispatchers require database leases/transactions before use.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/work` | Ranked items and visible device ownership |
| `PUT /api/work/assignment` | Save `{id, host, owner, team, due_at, escalate_to}`; device defaults use `id: "host:<name>"` |
| `PUT /api/work/exception` | Save `{id, host, reason, expires_at}` for an open finding |
| `DELETE /api/work/exception` | Revoke using `{id, host}` |
| `GET/POST /api/dynamic-groups` | List membership or create `{name, selector}` |
| `DELETE /api/dynamic-groups/{id}` | Delete an unused dynamic group |
| `GET/POST /api/change-plans` | List plans or schedule `{name, hosts, verb, arg, pilot_count, window_start, window_end}` |
| `POST /api/change-plans/{id}/promote` | Promote a verified pilot within the window |
| `POST /api/change-plans/{id}/cancel` | Stop undelivered work |
| `GET /api/hosts/{host}/verification` | Current evidence-based action status |

All API timestamps are RFC3339; dashboard date inputs use the operator's local time and convert to UTC. No workflow is enabled by merely installing this release: assignments, exceptions, dynamic groups, and change plans are created by operators.
