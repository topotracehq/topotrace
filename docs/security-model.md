# Security model

TopoTrace's authorization model layers three kinds of credential, each
narrower than the last, and access controls now extend that with
optional OAuth2/OIDC, AD/LDAP, or SAML 2.0 login for humans using the
dashboard -- any or all three can be enabled at once, alongside the
bearer-token schemes below.

## The master token

`-auth-token` (or `TOPOTRACE_AUTH_TOKEN`) is a single shared secret that
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

Configured with `-oauth-*` flags (see `cmd/topotrace -h` or the README),
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

## AD/LDAP login for the dashboard

Configured with `-ldap-*` flags. Unlike OAuth/SAML there's no external
IdP UI to redirect to -- the dashboard's own login form posts a
username/password to `POST /api/auth/ldap-login`, which binds a service
account (`-ldap-bind-dn`/`-ldap-bind-password`) to search the directory
for the user's entry (`-ldap-user-base-dn`, `-ldap-user-attr`), then
re-binds as that entry's own DN with the supplied password to verify
the credential -- the standard "search, then bind" LDAP auth pattern.
Group membership (`-ldap-group-attr`, default `memberOf`) maps to one
of the three fixed roles via `-ldap-role-map`, matched by full DN or
bare CN. Shares the same session store as OAuth and SAML, so all three
can be enabled at once.

This endpoint has no built-in rate limiting or account lockout -- rely
on the directory's own lockout policy (most AD/LDAP deployments already
enforce one) or a reverse proxy in front of it. See `internal/ldap`'s
doc comment for this package's scope (simple bind and a single-filter
search only, no SASL, no paging) and its "solid first draft, untested
against a live directory" caveat.

## SAML 2.0 SSO login for the dashboard

Configured with `-saml-*` flags. SP-initiated only: `GET
/api/auth/saml/login` redirects to the IdP's SSO endpoint, and the IdP
posts a signed assertion back to `POST /api/auth/saml/acs`. The user's
NameID (or an `email`/`mail` attribute) maps to a role via
`-saml-role-map`, same email/domain syntax as `-oauth-role-map`. SP
metadata for the IdP-side setup is at `GET /api/auth/saml/metadata`.

**Read `internal/saml`'s doc comment before enabling this against a
production IdP.** Full XML-DSig signature verification requires exact
W3C Exclusive Canonicalization, a genuinely hard transform to implement
correctly by hand -- getting it subtly wrong is exactly the kind of bug
that becomes a silent authentication bypass. Rather than risk that,
this package verifies signatures over the assertion's *exact original
bytes* (enveloped-signature only, no re-canonicalization), which is
correct for every mainstream IdP's typical output (Okta, Azure AD/Entra
ID, ADFS, Google Workspace) and fails *closed* on anything it can't
handle -- but it is not a general XML-DSig verifier, does not support
encrypted assertions, and has never been round-tripped against a live
IdP in this environment. Test it against your actual IdP's real
response format before relying on it to gate anything real.

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
## Site worker boundary

Site workers use separate hashed bearer credentials limited to polling and
returning their own jobs. Worker registration and job approval require an
unscoped administrator. Administrative SSH/WinRM credentials stay on each
worker. Its local address allowlist and pinned ingest destination restrict
the work it accepts. Agent installation is privileged and uses separate
per-host enrollment tokens; successful installation is not counted as a
completed deployment until a fresh report is observed. See
[Discovery & remote deployment](site-operations.md) for transport,
privilege, lease, revocation, and recovery details.
