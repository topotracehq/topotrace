# Agents & enrollment

## Reporting health and device visibility

The **Visibility → Agent health** view combines reporting status with evidence
coverage. A successful check-in does not mean every inventory category was
collected successfully, and complete evidence does not mean a device is secure.

| Status | Meaning |
|---|---|
| Healthy | Reports are arriving within the recorded cadence, with no newer failure. |
| Failing | A report failed after the last successful report, or no report has ever succeeded. |
| Late | The last success is more than twice the median recorded reporting interval ago. |
| Missing | The last successful report or legacy inventory is over 24 hours old. |
| Never | No successful report or legacy inventory is recorded. |
| Unknown | Inventory exists, but reporting cadence tracking is unavailable. |

Missing takes precedence over a recent failure when the last success is more than
24 hours old. The failure count is cumulative, not a count of consecutive errors.
Health and coverage use the snapshot time shown on the page; select **Refresh**
to retrieve current evidence. Group-scoped keys see only their devices.

For un-agented equipment, use **Visibility → Discovery review** after submitting
a discovery report. A managed match uses host names or recently collected IPv4
addresses; unmatched devices need review. An administrator can mark equipment
approved or unauthorized with a reason. This does not enroll the device or block
its network access. See **Device Visibility & Demo Walkthrough** for a ready-made
sample presentation of these states.

## Tracked enrollment

TopoTrace never pushes an agent onto a remote host or holds credentials to
log into one -- "deploy from the interface" means **self-service,
tracked enrollment**: the **Agents** tab mints a named, host-scoped,
revocable token; you paste the install command it gives you onto the
target host yourself; the host reports in under its own steam from
then on.

An enrollment token only ever authorizes that one host's fact reports
(`POST /api/mobile-report`, the TCP `TOPOTRACE1` protocol, or
`POST /api/airgap-report` -- see below). It can never queue a
remediation action, read another host's data, or call any other
endpoint. Revoke it from the Agents tab and that host immediately
stops being trusted.

`POST /api/cloud-report` is the one exception: a single scan
legitimately reports many instances under one credential, which
doesn't fit a token scoped to exactly one host, so that endpoint
requires the server's master token instead (see the Cloud agents
section below).

## Reporting paths

| Path | Transport | Used by |
|---|---|---|
| TCP `TOPOTRACE1` | raw socket, gzip+tar payload | Linux, macOS, Windows agent scripts |
| `POST /api/mobile-report` | JSON over HTTPS | Android app, iOS Shortcuts flow |
| `POST /api/cloud-report` | JSON over HTTPS | AWS, Azure, GCP scanners |
| `POST /api/airgap-report` | JSON over HTTPS, base64 payload | the air-gapped import flow |
| `POST /api/discover-report` | JSON over HTTPS | `cmd/discover`'s network sweep |

Every one of these ends up going through the exact same
`UpsertHost`/`UpsertFact` path (or, for discovery, a separate
`DiscoveredAsset` record -- see below) -- change tracking, staleness,
posture, vulnerability correlation, and compliance scoring all apply
uniformly no matter which door the data came in through.

## Discovered assets vs. managed hosts

A host you've enrolled and that's actively reporting facts is a
**managed host** (`model.Host`) -- the thing every other doc page and
dashboard view is about. A device `cmd/discover`'s network sweep found
open ports on, but that has no agent and no enrollment, is a
**discovered asset** (`model.DiscoveredAsset`) -- a much thinner
record (IP, open ports, best-guess service banners, first/last seen)
meant to answer "what's on this network that isn't inventoried yet,"
not to carry full fact history. Promoting a discovered asset into a
real enrolled host is a manual step (create an enrollment for it,
install an agent) -- TopoTrace doesn't do that automatically.

## Air-gapped hosts

`agent/airgap/`'s tool runs the exact same local fact-collection
commands the Linux/macOS/Windows scripts do, then gzip+base64-encodes
the result instead of sending it over a network the host doesn't have.
Carry that text blob to a machine that *can* reach TopoTrace (a USB
stick, retyping it, whatever your air-gap's sneakernet allows) and
paste it into the Agents tab's **Air-gapped import** panel, or `POST`
it directly to `/api/airgap-report`. There's no image/QR decoding on
the server side -- if you generate a QR code for the small-payload case
(see that tool's own README for the size limits this runs into), any
generic phone QR-scanner app turns it back into the same base64 text
for you to paste.

## Cloud agents

`agent/aws`, `agent/azure`, and `agent/gcp` are read-only, one-shot CLIs
that list instances/VMs in one cloud account and report them to
`POST /api/cloud-report` in the same `UpsertHost`/`UpsertFact` shape as
every other reporting path. They're stdlib-only Go (no AWS/Azure/GCP
SDK) -- this dev environment has no route to fetch one -- so each
implements just enough of its cloud's auth scheme by hand:

| Agent | Auth | API called |
|---|---|---|
| `agent/aws` | Hand-rolled SigV4 request signing from an access/secret key pair (or session token) | EC2 `DescribeInstances` (Query API, XML response) |
| `agent/azure` | Standard OAuth2 client-credentials flow against Azure AD (service principal client ID + secret) | Azure Resource Manager `virtualMachines` list (REST, JSON, paginated via `nextLink`) |
| `agent/gcp` | Hand-rolled RFC 7523 JWT-bearer OAuth2, signed with a service-account key file | Compute Engine aggregated instance list (REST, JSON, paginated via `nextPageToken`) |

Each one prints what it found to stdout/stderr and, unless run with
`-dry-run`, POSTs a report to `-server`'s `/api/cloud-report` using
`-token`. That token must be TopoTrace's **server master token**, not a
per-host enrollment token -- see "Tracked enrollment" above for why.
Credentials the agent itself needs (AWS keys, the Azure service
principal secret, the GCP service-account JSON) belong to that cloud
provider, not to TopoTrace, and are supplied via flags or the provider's
usual environment variables; TopoTrace never sees or stores them.

```
go run ./agent/aws   -region us-east-1 -server http://localhost:8080 -token <master-token>
go run ./agent/azure -tenant <tenant-id> -client-id <id> -client-secret <secret> \
    -subscription <subscription-id> -server http://localhost:8080 -token <master-token>
go run ./agent/gcp   -project <project-id> -key-file service-account.json \
    -server http://localhost:8080 -token <master-token>
```

Each instance is reported under its cloud name/ID as the host, with a
`cloud_instance` fact carrying provider-specific details (instance
type/size, power state, region/location/zone, tags). Re-running an
agent is safe and idempotent -- it's just another fact report, and
existing change-tracking/staleness logic treats a stopped-then-started
instance the same as any other fact change on a managed host.

**Not verified against live cloud accounts.** All three agents were
written and manually reviewed against each provider's published API
docs and example responses, but this dev environment has no AWS,
Azure, or GCP credentials and no route to those APIs, so none of the
three has actually been round-tripped against a real account. Treat
them as solid first drafts and test against a real (or sandboxed)
account before relying on them.
