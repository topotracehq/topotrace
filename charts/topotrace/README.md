# TopoTrace Helm chart

Deploys the whole stack on Kubernetes: the topotrace server (Deployment +
Services for the API and the raw ingest port), an optional Postgres
backend (StatefulSet + PVC), and two ways to run the existing agent
script as a real scheduled workload instead of by hand -- a CronJob and,
optionally, a one-pod-per-node DaemonSet.

## Prerequisites

- A Kubernetes cluster to point `helm`/`kubectl` at. The easiest option
  if you're on Docker Desktop: enable Kubernetes in Docker Desktop's
  settings -- its cluster shares Docker Desktop's own image cache, so
  locally-built images (below) are already visible to it, no extra load
  step. `kind` or `minikube` work too, but need an explicit image-load
  step (see below).
- `helm` 3.x and `kubectl`, pointed at that cluster.
- The images built locally (nothing is published to a registry):

  ```
  # From the repo root:
  docker build -t topotrace:latest .
  docker build -f agent/ubuntu/Dockerfile -t topotrace-ubuntu-agent:latest .
  ```

  With `kind`, load them into the cluster explicitly:
  ```
  kind load docker-image topotrace:latest
  kind load docker-image topotrace-ubuntu-agent:latest
  ```
  With `minikube`:
  ```
  minikube image load topotrace:latest
  minikube image load topotrace-ubuntu-agent:latest
  ```
  (Docker Desktop's built-in Kubernetes needs neither step.)

## Install

```
helm install topotrace charts/topotrace
```

That's the default: memstore replaced by a real Postgres StatefulSet
(`postgres.enabled: true` by default), a CronJob agent reporting in every
15 minutes, the DaemonSet variant off, RBAC on but scoped to nothing
(see below), and NetworkPolicy on.

Read what it printed (`helm status topotrace` to see it again) -- it has the
exact `kubectl port-forward` command for the dashboard and how to
trigger an agent run immediately instead of waiting for the schedule.

Override anything with `-f myvalues.yaml` or `--set key=value`; every
knob is documented in `values.yaml` itself, in place, rather than
duplicated here. A few worth calling out specifically:

```
# Turn on the one-pod-per-node agent too
helm upgrade topotrace charts/topotrace --set agent.daemonset.enabled=true

# Skip Postgres, run memstore (data lost on pod restart)
helm upgrade topotrace charts/topotrace --set postgres.enabled=false

# Point an agent outside the cluster at this cluster's NodePort
kubectl get nodes -o wide   # pick any node's IP
# then: --topotrace-host <that-ip> --topotrace-port 30909

# Turn auth on (also wires --token into both agent variants automatically)
helm upgrade topotrace charts/topotrace --set auth.token=some-shared-secret

# ...and a webhook once you've turned auth on and created a policy
helm upgrade topotrace charts/topotrace \
  --set auth.token=some-shared-secret \
  --set webhooks.urls="https://example.com/hooks/topotrace"
```

`auth.token` (or `auth.existingSecret`, for anything beyond a quick
local test -- see the comment in `values.yaml`) is the one value that
changes three templates at once: it adds `TOPOTRACE_AUTH_TOKEN` to the
server Deployment, and `--token`/`TOPOTRACE_TOKEN` to whichever agent
variant(s) are enabled, all reading the same Secret
(`secret-auth.yaml`, or your own via `existingSecret`) -- so there's no
world where the server has a token configured but the chart's own
agents don't know it, or vice versa. Leave it unset and the whole chart
behaves exactly like it did before this existed: no `-auth-token`, every
`GET` and board write open, remediation/policies/API keys unavailable.
See the main README's "Authentication, roles & remediation" section for
what turning it on actually changes server-side.

## Design notes worth knowing before you present this

**Why a StatefulSet for Postgres, at replicas=1.** A StatefulSet's value
here isn't horizontal scaling (Postgres doesn't gain anything from more
StatefulSet replicas without real streaming replication, which this
doesn't set up) -- it's the stable identity and the per-pod
PersistentVolumeClaim that survives the pod being rescheduled. That's the
actual reason to reach for a StatefulSet instead of a Deployment+PVC here,
and it's worth being able to say precisely why rather than "StatefulSet
because it's a database."

**Why RBAC is real but grants nothing by default.** Nothing in this
chart calls the Kubernetes API today -- the server talks to Postgres and
answers HTTP, the agent talks to the ingest port over its own protocol.
The correct least-privilege posture for that is no ServiceAccount token
at all, which is what `automountServiceAccountToken: false` on every
pod enforces explicitly rather than leaving to chance. `rbac.
grantPodReadAccess` (off by default) is there for a specific future
feature -- an in-cluster-aware agent reporting a pod count/namespace
fact via the API -- and grants exactly `get`/`list` on Pods in this
namespace, nothing more, only to the agent ServiceAccount, only when you
turn it on. Turning that value on today does nothing yet, since the
agent script doesn't call the API; that's deliberately a separate,
not-yet-built piece of work (see the main repo README's open items).

**What the DaemonSet's `hostPID` actually buys you.** Less than you'd
guess for today's fields: `/proc/cpuinfo` and `/proc/meminfo` already
reflect the real node's hardware inside an ordinary container, not a
cgroup-scoped view, because those specific procfs files aren't
PID-namespace-virtualized (a genuinely common container-internals
surprise -- ask anyone who's debugged "why does my container see the
host's full CPU count"). `hostPID`/`hostNetwork` matter for the fields
this project doesn't collect *yet* -- listening ports, local users,
running processes -- which are real host state, not host hardware specs,
and do need that visibility. It's wired in now so the DaemonSet doesn't
need a breaking change later.

**NetworkPolicy's actual scope.** It restricts pod-to-pod traffic within
the cluster: only pods labeled `topotrace.io/network-role: agent` (this
chart's own CronJob/DaemonSet) can reach the raw ingest port from inside
the cluster; the API/dashboard port stays open. Traffic arriving through
the ingest Service's NodePort from *outside* the cluster is a different
enforcement path that depends on your CNI (Calico/Cilium enforce it,
not every CNI does) -- this NetworkPolicy doesn't claim to cover that,
and the template says so in a comment rather than leaving it implied.

## Verification status

Be direct about this rather than letting it pass as "tested": there is
no Kubernetes cluster (and no `helm`/`kubectl` binaries) available in the
sandbox this chart was written in, so nothing here has gone through an
actual `helm install`/`kubectl apply` on a real cluster. What *was* done,
concretely:

- Every template parses as valid Go template syntax (a standalone
  verification harness, not part of this repo, parsed and *executed*
  all 12 template files against four different value combinations --
  defaults, everything optional turned on, Postgres disabled, and an
  `existingSecret` override -- exercising every `{{- if }}` branch in
  the chart).
- Every rendered manifest across all four scenarios (40 files total) was
  then parsed as YAML and checked for `kind`/`apiVersion` on every
  document, catching indentation/structure mistakes a template-syntax
  check alone wouldn't.
- The rendered output for each scenario was read manually end to end
  (Deployment, StatefulSet, CronJob, DaemonSet, RBAC, NetworkPolicy) to
  confirm it matches what's described above, not just that it parses.

What that doesn't cover: real scheduler behavior, real Postgres startup
timing against the `wait-for-postgres` init container, real DNS
resolution of the Service names, whether your specific cluster's default
StorageClass actually satisfies the PVC, or whether your CNI enforces
the NetworkPolicy the way the comments describe. You have Docker Desktop
-- `helm install` on your own machine is the real test, the same honesty
gap as the Docker Compose build and the PowerShell agent already had
before you confirmed those environments were available to you.
