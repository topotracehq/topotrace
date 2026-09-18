# Device visibility and demo showcase

Open **Visibility** for live device history, agent health, and discovery review.
Select **Demo showcase** (or open `/#/visibility/demo`) for a ready-to-present,
isolated sample fleet. Normal server authentication applies; sign in if it is
enabled. No setup or seeding is needed.

## Three-minute walkthrough

Use the **Demo scenario** selector for a new unauthorized device, a failed
change, and verified recovery. Select **Presentation mode** for larger text and
fewer setup controls, and **Branded demo report** for a printable handout.

1. **Device history:** show the Ubuntu and nginx upgrades on `demo-web-01`,
   the failed service on `demo-db-01`, and the disabled laptop firewall.
   Search by device, field, or value and filter by category.
2. **Agent health:** show healthy, failing, late, missing, never reported, and
   unknown reporting states. Expand collection evidence to explain why a
   reporting agent can still have outdated inventory categories.
3. **Discovery review:** show a managed address, an unknown device, an
   unauthorized appliance, and an approved printer with an old sighting.
   Try a sample review, then select **Reset demo** to restore the original story.

Demo data is rebuilt in a disposable in-memory store. It never writes live
inventory, audit entries, notifications, or device actions. Demo review changes
last only until the page is refreshed or left. Sample IPs use 192.0.2.0/24.

## Live behavior

History shows at most the most recent 100 changes per device, capped at 1,000
across the fleet. Search filters this returned window. History timestamps reflect
collection, not necessarily the exact time a device changed.

Agent health uses recorded reporting intervals; older inventory without agent
tracking is marked unknown, not healthy. A report more than 24 hours old is
missing. Collection evidence uses the existing four-category coverage checks.

Discovery matches host names and IPv4 interface addresses collected within 24
hours. Unmatched does not mean unauthorized: an unscoped administrator explicitly
reviews a device with a reason. Decisions persist and are recorded in the audit
trail. Approved and unauthorized decisions remain until reviewed again; they are
associated with the discovery record, not a cryptographically verified device
identity. Stale sightings cannot prove current presence or absence. Classification
does not block traffic or deploy an agent. Group-scoped accounts cannot see the
global discovery list.

API: `GET /api/visibility`, `GET /api/visibility?demo=1`, and
`PUT /api/discovered-assets/{id}/review` with `state` and `reason`.
