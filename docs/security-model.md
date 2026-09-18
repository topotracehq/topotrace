# Security model

Muster's authorization model layers three kinds of credential, each
narrower than the last, and access controls now extend that with an
optional OAuth2/OIDC login for humans using the dashboard.

## The master token

`-auth-token` (or `MUSTER_AUTH_TOKEN`) is a single shared secret that
always resolves to the `admin` role. It exists to bootstrap everything
else -- use it once to mint named, role-scoped API keys via
`POST /api/keys`, then prefer those for anything long-lived.

## Named API keys and roles

Three fixed roles, `readonly < remediate < admin`. A key created via
`POST /api/keys` is shown once; only its SHA-256 hash is ever stored.
Keys can optionally name a board group. The Visibility and agent-health endpoints
filter host evidence to that group. Per-verb custom roles are not supported.
Global discovery has no group ownership model, so the Visibility response omits
it for group-scoped keys, and discovery reviews require an unscoped administrator.

## Enrollment tokens

Deliberately the narrowest credential in the system: an enrollment
token authorizes exactly one host's fact reports and nothing else --
never remediation-result reporting, never any other endpoint. See the
"Agents & enrollment" page.

## OAuth2/OIDC login for the dashboard

Configured with `-oauth-*` flags (see `cmd/muster -h` or the README),
this adds a real browser login flow (authorization-code grant) in
front of the web dashboard: sign in with your identity provider, and
your email (or a configured claim) is mapped to one of the three fixed
roles via `-oauth-role-map` (e.g. `admin@example.com=admin,
*@example.com=readonly`). It sits *alongside* the bearer-token schemes
above, not instead of them -- a script or agent still authenticates
with a token; OAuth is specifically for a person clicking around the
UI, so a session lasts as long as its cookie rather than requiring a
token pasted into the Auth control every time.

**This is unverified against a live identity provider** -- see
`internal/oauth`'s doc comment and the top-level README for exactly
what was and wasn't testable in the environment this was built in.
Test it against your actual IdP (Google, Okta, Azure AD, GitHub, ...)
before relying on it to gate anything real.

## What's still a single shared secret, on purpose

Remediation's allow-listed verb set (`internal/remediate`) is the same
regardless of which credential queued it -- a human via the API, an
operator via the CLI, or the background evaluator acting on a policy
rule. There's no path from an unauthenticated network client to a host
actually running a command; every entry point funnels through the
same validation.

## Visibility reviews and demo isolation

Device classifications are operator decisions backed by a required reason,
actor, timestamp, and audit entry. They do not prove device identity or enforce
network access. IP addresses can be reassigned; an old approval should be reviewed
when equipment changes. Matching uses names and recent IPv4 interface evidence.

The Visibility **Demo showcase** uses a disposable sample store and retains the
normal read-access requirement. Its review controls change only the current
browser view. They do not call the live review-write endpoint, update inventory,
send notifications, or queue remediation. Refreshing restores the samples.

This differs from **Settings → Demo / simulator**, whose scenarios intentionally
write simulated audit events and can send notifications through configured
integrations. Use the Visibility showcase for a presentation without those
external effects. All pages outside that showcase still use live data.
