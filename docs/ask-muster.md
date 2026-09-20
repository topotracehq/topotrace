# Ask TopoTrace

A natural-language query surface over your fleet data, built on the
Anthropic Messages API -- but the pitch here isn't "there's a chatbot,"
it's **governed AI**: every question that gets asked, and the answer
TopoTrace gave, is recorded to the same audit log every other privileged
action in this project already goes through
(`Store.RecordAudit`, `GET /api/audit`).

## Choosing a model backend

Ask TopoTrace speaks two API shapes, selected with `-ai-backend`
(`MUSTER_AI_BACKEND`):

| Backend | Reaches | Needs |
| --- | --- | --- |
| `anthropic` (default) | Anthropic's Messages API | `-ai-api-key`; `-ai-model` optional, defaults to `internal/aiquery`'s built-in |
| `openai-compatible` | Hugging Face's Inference Providers router, and any server speaking OpenAI chat-completions: LM Studio, Ollama, vLLM, text-generation-inference | `-ai-base-url` and `-ai-model`; `-ai-api-key` optional |

Two implementations cover that much ground because the OpenAI
chat-completions shape has become the lingua franca of model serving.
Only the base URL changes between a hosted Hugging Face model and one
running on your own hardware.

### Anthropic

```
go run ./cmd/muster -ai-api-key "sk-ant-..."
# or: MUSTER_AI_API_KEY=sk-ant-... go run ./cmd/muster
```

### Hugging Face

```
go run ./cmd/muster \
  -ai-backend openai-compatible \
  -ai-base-url https://router.huggingface.co/v1 \
  -ai-model "Qwen/Qwen3-30B-A3B-Instruct-2507" \
  -ai-api-key "hf_..."
```

The token is a fine-grained Hugging Face token with the
"Make calls to Inference Providers" permission.

### A model you host

```
go run ./cmd/muster \
  -ai-backend openai-compatible \
  -ai-base-url http://your-host:11434/v1 \
  -ai-model "qwen3:30b-a3b"
```

Ollama listens on 11434 and LM Studio on 1234, both at `/v1`. Either
the bare `/v1` root or the full `/v1/chat/completions` URL works. No
API key is needed for a local server, and none is sent: an empty
`-ai-api-key` means the `Authorization` header is omitted entirely
rather than sent empty, which some servers reject.

**This is the option worth taking seriously for this product.** Ask
TopoTrace sends real fleet context with every question: host names,
addresses, installed software, CVE findings, policy rules. Sending that
to a third-party API is exactly the objection a security-conscious
buyer raises, and it is a fair objection. A model running on hardware
the operator controls means the inventory never leaves their network,
and the feature stops being a reason to fail a review.

The honest tradeoff is quality. A small self-hosted model is
noticeably worse than a frontier model at this, particularly at the
policy drafting below, which has to emit a valid rule. `Validate`
catches malformed drafts and both extra features fall back to
non-AI paths, so the floor is safe; the ceiling is lower.

### Reasoning models

A reasoning model (Qwen3, DeepSeek-R1 and similar) writes a hidden
scratchpad before its visible answer, and that scratchpad is charged
against the same token budget. Point Ask TopoTrace at one and the whole
budget can be spent thinking, leaving an empty answer and
`finish_reason=length`.

Two mitigations are built in: this backend raises any caller's token
budget to a floor that leaves room for both, and an empty answer is
reported as what it actually is rather than as a blank mystery.

The better fix is to use a non-reasoning build. On Ollama, Qwen3's
`-instruct-2507` tags are non-thinking:

```
ollama pull qwen3:30b-a3b-instruct-2507-q4_K_M
```

That also makes answers land sooner, since none of the time is spent
on tokens nobody reads. For a fleet question there is not much for a
model to reason about anyway: the context already contains the facts,
and the job is to summarize them accurately.

### Switching without a restart

All of the above can also be set from the Settings page's Ask TopoTrace
card, or with `PATCH /api/settings` (`ai_backend`, `ai_base_url`,
`ai_model`, `ai_api_key`, `ai_disable`), and takes effect immediately.
Values saved that way persist to `<data-dir>/settings-overrides.json`
at mode 0600. As everywhere else in TopoTrace, an explicit flag or env var
beats a saved override, so a value pinned at deploy time cannot be
changed from the dashboard.

Left unconfigured entirely, `POST /api/ask` answers with a clear
"not configured" error rather than ever making an outbound request
with no credential.

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
   `/api/hosts/{host}/compliance` already use, so Ask TopoTrace's answers
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
conversation state kept server-side (the browser's Ask TopoTrace panel
keeps a client-side transcript purely for display; the audit log is
the real record). No memory across questions today: each question is
answered from a fresh snapshot, not a running conversation.

## Beyond questions: drafting policies and writing the summary

Two more things Ask TopoTrace does, both built so the AI proposes and a
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
other Ask TopoTrace call. Neither has been exercised against a live
Anthropic key from this environment; the heuristic and template paths
were.
