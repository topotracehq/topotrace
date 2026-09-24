# Getting started

TopoTrace is a hardware/software/configuration inventory tool: agents
report facts about a host, TopoTrace stores and diffs them over time, and
scores/policies/webhooks act on what changed.

## Running the server

```
go run ./cmd/topotrace
```

Defaults to an in-memory store snapshotted to `./data/topotrace.json`, an
HTTP API + web dashboard on `:8080`, and a raw-TCP agent ingest daemon
on `:9090`. See the top-level README's "Running it" section for
Docker, Kubernetes, and standalone-systemd paths, and `-postgres-dsn`
for a real database backend.

## Getting a host reporting

Pick the path that matches what you're inventorying:

- **Linux/macOS/Windows machine you can put a script on** -- download
  the agent script from the **Agents** tab (or `GET
  /api/agents/download/{linux,macos,windows}`), create an enrollment
  for it first, and run the one-line install command the tab shows you.
- **Android phone** -- build `agent/android/` in Android Studio, enter
  the enrollment's server/host/token in its setup screen.
- **iPhone** -- no app; follow `agent/ios/README.md`'s Shortcuts-based
  walkthrough.
- **A host with no network access at all** -- see `agent/airgap/`'s
  README and this doc set's "Agents & Enrollment" page's air-gapped
  section: it runs the same local fact collection, then hands you a
  base64 blob to paste into the dashboard from a machine that *can*
  reach TopoTrace.
- **A cloud account (AWS/Azure/GCP)** -- see `agent/aws`, `agent/azure`,
  `agent/gcp`: read-only, credential-scoped scanners that report
  compute instances as hosts, the same way an OS agent reports a
  physical/virtual machine.
- **A network segment with un-agented devices on it** -- `cmd/discover`
  does a TCP-connect sweep and reports what it finds as a distinct
  "discovered, not managed" asset, not a full host record.

## Where to go next

Once something's reporting, open the dashboard at `/` --
**Hosts** for the raw list, **Board** for a Kanban view grouped by
whatever tags you assign, **Fleet** for a fleet-wide rollup,
**Compliance** for posture/vulnerability/software-list scoring, and
**Agents** to manage enrollments and downloads.

Open **Work queue** to prioritize findings, assign owners and deadlines, manage
expiring exceptions, create dynamic groups, and schedule staged service restarts.
See **Work Queue & Governed Changes** in Docs for supported actions and limits.

Open **Device visibility** for searchable device changes, agent reporting health,
and discovered-device review. Open **Data & recovery** when you need a portable
workspace backup or want to restore missing configuration.

After installing a new server binary, restart the service and refresh the browser
with Ctrl+F5 if the new navigation has not appeared.

## Navigate the dashboard

Use the labeled sidebar to switch between Overview, Operations, Workspace,
Manage, and Help. **Manage** contains editable settings, data recovery, and
subscription status. **Help** contains the searchable help center and product
information. On smaller screens, select Menu. See
[Dashboard & Navigation](interface.md) for the complete layout.
