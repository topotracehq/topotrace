# Security model

TopoTrace's authorization model layers three kinds of credential, each
narrower than the last, and access controls now extend that with
optional OAuth2/OIDC, AD/LDAP, or SAML 2.0 login for humans using the
dashboard -- any or all three can be enabled at once, alongside the
bearer-token schemes below -- plus SCIM provisioning, attribute-based
host visibility/masking, SIEM-exportable audit logging, org-wide MFA
enforcement, and session management controls layered on top of them.

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

## SCIM 2.0 provisioning and JIT deprovisioning checks

Configured with `-scim-token`. Every login method above computes a role
live from the identity provider on each login and has never stored
anything about the person logging in -- fine for authenticating them,
but it means there was no way to say "this person is deprovisioned,
refuse them" any faster than the IdP itself catching up, which for a
slow HR-to-IdP pipeline can be days. `internal/directory` fixes that
with a persisted user record per email (`kind: "user"` in the generic
document store), and `/scim/v2/Users` lets an external identity system
(Okta, Azure AD/Entra ID, OneLogin, ...) push create/update/deactivate
operations to it directly, bearer-authenticated with `-scim-token` -- a
separate, narrow-purpose credential from the three API-key roles.
Deactivating a user through SCIM takes effect at their *next* login
attempt, regardless of what OAuth/LDAP/SAML still say about them, and
also immediately revokes every live dashboard session they currently
hold.

For customers who don't run SCIM at all, every successful OAuth/LDAP/
SAML login still JIT-provisions (or refreshes the role on) a directory
record automatically -- so the directory, and its deactivation check,
apply either way.

**This implements a practical subset of RFC 7644**, not a full SCIM 2.0
server: `/Users` create/read/list/update/deactivate only, no `/Groups`,
no filter query language beyond an exact `userName eq "..."` match, no
bulk operations. See `internal/directory` and `internal/api/
enterprise.go`'s doc comments, and test against your actual IdP's SCIM
app before relying on it.

## Attribute-based host visibility and field masking

Configured via `POST /api/acl/policies` (admin-only) -- no flag, since
policies are data, not startup configuration. `internal/acl` evaluates
every policy against the *viewer's* role/email and a host's existing
`Tags`/`Group` metadata (nothing new to tag), on every read, never
pre-computed: `AllowTags`/`DenyTags` decide whether a viewer sees a host
at all ("a user can see prod hosts but not the DB tier" is exactly an
`AllowTags: ["prod"]` or `DenyTags: ["db-tier"]` policy), and
`MaskFields` (currently just `hostname` -- TopoTrace doesn't store an
IP or credentials directly on a host record) redacts a field on hosts
the viewer can otherwise see. `POST /api/acl/preview` (admin-only) shows
exactly what a given role or email would see across every current host,
without needing to actually log in as them.

Masking is applied at exactly one choke point (`maskHostForViewer`,
called from the host list/detail handlers) -- a new endpoint that
starts returning host data through a different path must call it too;
nothing in `internal/acl` can enforce that on its own. A viewer with no
matching policy at all sees hosts exactly as before this feature
existed -- ACL is additive restriction, not default-deny.

## Immutable, SIEM-exportable audit logging

Every authenticated write and every login (`Store.RecordAudit`) has
always been immutable and append-only -- there is no delete or edit
method on the audit trail, by design, and it cannot be turned off. What
was missing was getting it into a real SIEM: `-siem-backend` now
includes `syslog` alongside the existing `splunk-hec`/`sumo-http`/
`logrhythm-webhook` options (`internal/siemforward`), forwarding one
RFC-5424-shaped line per event over TCP to a syslog receiver -- most
SIEMs (QRadar, Microsoft Sentinel, Elastic via a syslog input,
ArcSight) accept one directly. `GET /api/audit` remains the trail's own
read path regardless of whether forwarding is configured.

**S3/object-storage export is not implemented** -- it would need an AWS
SDK this environment has no route to vendor, unlike every other backend
here, which is stdlib `net/http`/`net` only. A webhook or syslog
receiver in front of your own S3 pipeline is the documented workaround
today.

## Org-wide MFA enforcement policy

Configured with `-mfa-required`, `-mfa-roles`, `-mfa-grace-days`, and
`-mfa-issuer`. `internal/mfa` implements TOTP (RFC 6238) -- SHA-1, 30
second step, 6 digits, the universal defaults nearly every authenticator
app (Google Authenticator, Authy, 1Password, ...) assumes. When policy
requires MFA for a role and an account has no enrollment yet, login
still succeeds within a configurable grace window (measured from when
the directory record was first created, not from when the policy was
turned on) but is flagged `mfa_setup_required` so the dashboard can
prompt enrollment; once the window passes, login is refused until an
admin intervenes. An account with a *completed* enrollment gets a
session that authenticates nothing beyond `POST /api/auth/mfa/enroll`/
`/confirm`/`/verify` until a valid code is presented.

**Untested against a real authenticator app** in this environment --
the HOTP core is verified against RFC 4226's own published test
vectors (see `internal/mfa`'s tests), which confirms the arithmetic is
correct, but that is not the same thing as a phone actually scanning
the QR code and agreeing. Verify with a real app before relying on it.

## Session management controls

`-session-idle-timeout` (default 30m) expires a dashboard session after
that long without an authenticated request touching it, independent of
its fixed 12-hour absolute lifetime. `-session-max-concurrent` (default
5) caps how many live sessions one account may hold at once, evicting
the oldest once a new login would exceed it. `GET /api/auth/sessions`
(admin) and `GET /api/auth/sessions/mine` (self) show every live
session's email/role/created/last-seen -- deliberately never the raw
session ID itself, since that would hand out a bearer-equivalent
credential for hijacking a listed session. `POST /api/auth/sessions/
revoke {"email":...}` (admin) force-logs-out every session for one
account; the same happens automatically on SCIM/directory
deactivation.

Sessions remain in-memory only, same as before this round -- see
"OAuth2/OIDC login for the dashboard" above for why, and its
consequences for restarts/multi-replica deployments.

## License and seat usage dashboard

`-licensed-seats` and `GET /api/license/usage` (admin-only) report
active seats against the contracted count, with a daily usage
snapshot (`internal/license`, backed by the same store.Document
mechanism as the user directory) providing up to 90 days of trend and
an audit-logged warning once usage reaches 90% of the licensed count.
"Active seat" is defined identically to the SCIM/JIT user directory
(#22) -- there is no separate seat record to fall out of sync. This is
reporting, not enforcement: reaching or exceeding the licensed count
does not block a login or a new SCIM-provisioned user.

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
