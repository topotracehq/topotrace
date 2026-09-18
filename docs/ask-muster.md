# Ask Muster

A natural-language query surface over your fleet data, built on the
Anthropic Messages API -- but the pitch here isn't "there's a chatbot,"
it's **governed AI**: every question that gets asked, and the answer
Muster gave, is recorded to the same audit log every other privileged
action in this project already goes through
(`Store.RecordAudit`, `GET /api/audit`).

## Turning it on

```
go run ./cmd/muster -ai-api-key "sk-ant-..."
# or: MUSTER_AI_API_KEY=sk-ant-... go run ./cmd/muster
```

Left unset, `POST /api/ask` answers with a clear `503 "not configured"`
error instead of ever making an outbound request with no credential.
`-ai-model`/`MUSTER_AI_MODEL` optionally overrides the model id
(`internal/aiquery`'s built-in default otherwise).

## How it works

1. **Gate.** `POST /api/ask` requires at least a `readonly` credential
   -- the same tier as every other read endpoint, since asking a
   question about the fleet is a read, not a write.
2. **Build context.** The server gathers a compact JSON snapshot
   straight from the Store: fleet summary, every host's platform/
   group/tags/staleness, posture score and findings, known-vulnerable
   packages, software-allowlist violations, shadow AI detections,
   compliance score, plus the configured policy rules, software rules,
   and discovered-but-unmanaged assets. This reuses the exact same
   `complianceInput` computation the Compliance tab and
   `/api/hosts/{host}/compliance` already use, so Ask Muster's answers
   are grounded in the same numbers the rest of the dashboard shows.
3. **Call the model.** `internal/aiquery.Ask` POSTs that context plus
   the question to the Anthropic Messages API (stdlib `net/http` only,
   no SDK -- the same integration style as `internal/vuln`'s OSV.dev
   client and `internal/oauth`'s token exchange) with a system prompt
   instructing the model to answer only from the supplied snapshot,
   not to invent hosts or findings that aren't there.
4. **Log it.** The question and answer (both truncated) are recorded
   to the audit log as an `ask-muster` entry, actor-attributed the same
   way every other API write is (the credential's name, or `"master"`).

## What it isn't

Not a general-purpose chatbot, not a tool-use agent, not a place to
paste arbitrary data -- one request in, one answer out, no
conversation state kept server-side (the browser's Ask Muster panel
keeps a client-side transcript purely for display; the audit log is
the real record). No memory across questions today: each question is
answered from a fresh snapshot, not a running conversation.

## Beyond questions: drafting policies and writing the summary

Two more things Ask Muster does, both built so the AI proposes and a
person decides:

- **Draft a policy rule from a description.** On the Fleet tab's policy
  form, type what you want in plain English ("flag any prod host whose
  posture score drops below 75 and restart nginx, but ask me to approve
  first") and `POST /api/ask/draft-policy` fills the form's fields --
  kind, threshold, group, auto-remediation, require-approval -- with an
  explanation of why. The draft is validated against the fixed rule
  vocabulary and never created on its own; Create is still your click.
  Without an API key, keyword heuristics draft it instead and the UI
  says so.
- **Write the executive summary.** `POST /api/ask/summary` hands the
  same `report.Data` the executive report is built from to the model
  with a strict "only these numbers, name the hosts, four short
  paragraphs, one recommendation" prompt. Without a key a deterministic
  template produces the same four paragraphs from the numbers directly,
  labeled as such.

Both go through `aiquery.Complete`, the one place that knows the
Messages API wire format, and both record an audit entry like every
other Ask Muster call. Neither has been exercised against a live
Anthropic key from this environment; the heuristic and template paths
were.
