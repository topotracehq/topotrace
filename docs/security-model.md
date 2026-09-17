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
There is no finer-grained scoping yet (per-group or per-verb keys) --
see the top-level README's "What's here vs. what's next."

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
