# Compliance & software lists

## Software allow/deny lists

A `SoftwareRule` matches installed-software package names
(case-insensitive, optional trailing `*` wildcard), scoped to a board
group or every host. **Deny** rules always apply -- any match is a
violation. **Allow** rules only start enforcing once at least one
exists for a scope: an empty allowlist means "no opinion yet," not
"everything is unauthorized," the same absence-is-unknown-not-bad
principle posture scoring already uses.

Manage them under `GET/POST /api/software-rules` (`admin` to write),
or from the dashboard's **Compliance** tab. Violations show up at
`GET /api/hosts/{host}/software-violations`, and the background
evaluator records an audit entry plus fires a `software_violation`
webhook the moment one appears -- the same trail policy-rule
violations already leave.

## Compliance frameworks

A `compliance.Framework` is a small, fixed set of named checks scored
as a percentage. **Muster Baseline**, the one built in today, checks:
reporting recently (not stale), a posture score of at least 70, no
known-vulnerable packages, and no denied/unauthorized software.

This is explicitly **not** a certified mapping to CIS Benchmarks,
SOC 2, PCI DSS, or any other real standard -- it's built entirely from
signals Muster already computes for real, the same "small, honest
illustration" spirit as the static vulnerability dataset. Treat it as
the foundation a real control mapping could sit on, not a substitute
for one.

`GET /api/hosts/{host}/compliance` evaluates every framework for one
host; `GET /api/compliance/summary` rolls Baseline up fleet-wide
(average score, how many hosts pass every check outright).
