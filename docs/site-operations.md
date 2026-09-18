# Discovery & remote deployment

Muster supports site-local workers for scheduled TCP discovery and staged installation of agents on new Linux or Windows hosts. Workers poll the central API; the dashboard does not need inbound administrative access to each site.

## Register a worker

1. Open **Discovery & deployment** with an unscoped administrator credential.
2. Register a named worker. Copy its token immediately; it is shown only once. The server stores its hash.
3. Build the worker with `go build -o site-worker ./cmd/site-worker` on Linux, or `go build -o site-worker.exe ./cmd/site-worker` on Windows.
4. Place its configuration and administrative credential references on the worker. Restrict file permissions to the worker operator. Set the token in the environment named by `token_env`.
5. Run `./site-worker -config site-worker.json`. It polls every 15 seconds. Use `-once` for a single poll. Run it under your existing service supervisor for continuous schedules.

Example configuration (replace every example destination and path):

```json
{
  "server": "https://muster.example.com",
  "token_env": "MUSTER_SITE_TOKEN",
  "allowed_cidrs": ["10.20.30.0/24"],
  "ingest_host": "muster.example.com",
  "ingest_port": 9090,
  "profiles": {
    "linux-office": {
      "user": "deployment",
      "identity_file": "/etc/muster-worker/id_ed25519",
      "known_hosts": "/etc/muster-worker/known_hosts"
    },
    "windows-office": {
      "user": "DOMAIN\\deployment",
      "password_env": "MUSTER_WINDOWS_PASSWORD"
    }
  }
}
```

The API connection requires HTTPS with normal certificate validation. `allow_http: true` is an explicit option for a protected lab network; bearer credentials would then travel without transport encryption. Agent reports use the existing Muster ingest protocol; protect that path with your existing private network or TLS transport. The worker checks both its local address allowlist and its pinned ingest destination before installation.

## Discovery workflow

Create a named job with an IPv4 range of /20 or smaller, 1–32 TCP ports, and an optional recurrence of 1–720 hours (0 means one scan). Review the saved draft before pressing **Start discovery**. Discovery never starts just by creating the draft.

Each worker uses 32 concurrent address checks with a 500 ms connection timeout. Jobs have a 20-minute worker deadline and 30-minute lease. Large, slow ranges can time out; split them into smaller ranges. Only hosts accepting at least one selected port appear. A missing result does not prove a host is offline. Scanning does not retrieve credentials or execute target commands.

Results retain first/last seen timestamps and open ports. Repeated observations merge by worker and address; identical addresses at different sites remain separate. Port observations have low identification confidence and do not establish OS or identity. Review devices before assigning enrollment host names. There is no automatic cross-site identity matching.

## Deployment workflow

1. Enter exact IPv4 addresses and unique host names, platform, worker-local credential profile, ingest destination, and pilot count.
2. Save and review the target list. Existing host names and targets already reserved by another deployment are rejected.
3. Run **preflight**. It checks remote authentication, administrative privilege, required utilities, scheduler availability, absence of a previous site-worker installation, and TCP reachability of the ingest endpoint. It makes no installation changes.
4. Once every target passes, explicitly **Start pilot**. Each installation rechecks readiness before writing.
5. Wait for the server to verify the enrollment and a report newer than the dispatch time. Command success remains **awaiting-report**.
6. Only after all pilot devices report can you **Promote remaining devices**.

Linux uses OpenSSH with BatchMode, strict known-host checking, a local identity file, and noninteractive sudo. Provision and verify host keys ahead of time. The deployment account must be permitted to run the installer as root. It installs a root-only agent wrapper in `/opt/muster-site-agent`, plus `muster-site-agent.service` and `.timer`. The timer runs every 15 minutes. The service currently runs as root, which gives it administrative collection and remediation privileges; choose the existing manual unprivileged installer if that is unsuitable.

Windows deployment requires a Windows worker with Windows PowerShell and a target configured for WinRM HTTPS, a trusted valid certificate matching its address, and administrative remoting credentials. Certificate verification and TrustedHosts are not weakened. It installs protected files under `%ProgramData%\MusterSiteAgent` and a `MusterSiteAgent` scheduled task running as SYSTEM every 15 minutes. PowerShell execution policy must permit the agent. The worker does not change execution policy.

The WinRM design follows Microsoft's [Invoke-Command documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command). This release has automated script-generation and state-transition checks; live Windows remoting and Task Scheduler verification must be performed with your pilot environment.

## Failure and recovery

Workers receive only their own jobs. Their tokens cannot call general administrative APIs. Revoke a worker from the page to stop future polling; revocation cannot stop a command already running on a target.

Installation credentials remain local. Per-host enrollment tokens are generated at dispatch; only hashes are retained on the server. Remote stdout/stderr are deliberately not uploaded because installers can expose secrets. Inspect target service/task and worker logs for troubleshooting.

A lost or expired lease becomes **uncertain** and is never automatically rerun. A worker retries delivery of its result, not execution of the install. A failed job stops the rollout. Cancellation stops future dispatch only and is refused while an operation is leased. It does not uninstall an agent or revoke its enrollment. Revoke enrollment credentials separately in Agents when necessary.

If installation partially completed, inspect the target and reconcile it manually. This version intentionally has no automated retry/reinstall; do not create replacement jobs to bypass an uncertain state. Cancelling a job releases reservations only for targets that have never received an enrollment token, so a corrected preflight-only job can be drafted again. Targets with dispatched enrollment credentials remain reserved. Back up the full server store: jobs, worker credential hashes, and sightings are not part of the limited workspace configuration export. Run one active Muster server per store; multi-replica job claiming needs transactional storage before it is supported.

## Permissions and endpoints

All `/api/sites` routes require an unscoped administrator. `/api/worker` routes require a dedicated worker credential.

- `GET /api/sites`: workers, jobs, and sightings.
- `POST /api/sites/workers`: register a worker; `DELETE /api/sites/workers/{id}` revokes it.
- `POST /api/sites/jobs`: create a validated draft.
- `POST /api/sites/jobs/{id}/{decision}`: `preflight`, `start`, `promote`, or `cancel`.
- `PUT /api/sites/assets/{id}`: set `review` to `new`, `reviewed`, or `ignored`.
- `POST /api/worker/poll`: claim one bounded task, or 204 when idle.
- `POST /api/worker/results/{id}`: submit outcome with the exact current lease.
