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

## Shadow AI detection

Alongside operator-defined software rules, Muster ships a built-in,
pre-seeded ruleset (`internal/allowlist.ShadowAIPatterns`) flagging
known AI desktop apps, CLI tools, and browser extensions --  ChatGPT,
Claude, Ollama, LM Studio, GitHub Copilot, Gemini, Perplexity, and
others -- found in a host's `installed_software` fact. No setup
required: every deployment can answer "do we have unauthorized AI
tooling anywhere" on day one, the same "invisible SaaS/tool sprawl"
problem enterprise browser security products build shadow-IT/shadow-AI
detection around.

An AI tool an operator has explicitly sanctioned via a `Kind: "allow"`
software rule matching its name is excluded -- approved software isn't
shadow IT. That check is independent of the generic allow/deny
enforcement above: sanctioning one AI tool for a group never turns on
full allowlist enforcement (flagging every *other* package in that
scope) as a side effect.

Shadow AI detections show up as their own labeled `shadow_ai` field at
`GET /api/hosts/{host}/software-violations` (next to, never mixed
into, the generic `violations` list), as their own card on a host's
detail page, as a `hosts_with_shadow_ai`/`total_shadow_ai_findings`
pair on `GET /api/summary` and the Fleet tab, and as their own Muster
Baseline compliance check (`no-shadow-ai`).

## Compliance frameworks

A `compliance.Framework` is a small, fixed set of named checks scored
as a percentage. **Muster Baseline**, the one built in today, checks:
reporting recently (not stale), a posture score of at least 70, no
known-vulnerable packages, no denied/unauthorized software, and no
unauthorized AI tools detected (shadow AI, see above).

This is explicitly **not** a certified mapping to CIS Benchmarks,
SOC 2, PCI DSS, or any other real standard -- it's built entirely from
signals Muster already computes for real, the same "small, honest
illustration" spirit as the static vulnerability dataset. Treat it as
the foundation a real control mapping could sit on, not a substitute
for one.

`GET /api/hosts/{host}/compliance` evaluates every framework for one
host; `GET /api/compliance/summary` rolls Baseline up fleet-wide
(average score, how many hosts pass every check outright).
