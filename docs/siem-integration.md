# SIEM integration

TopoTrace can forward its own audit trail to a real SIEM, so events that
already get recorded to `GET /api/audit` (policy violations,
remediation, Ask TopoTrace queries, enrollment/key management, OAuth
logins, and every other authenticated write) also reach an operator's
existing security tooling -- not just TopoTrace's own dashboard.

This is built on a small `Forwarder` interface
(`internal/siemforward.Forwarder`, `Send(ctx, event) error`) with three
implementations today (Splunk, Sumo Logic, LogRhythm) and room for more
without touching any call site: every place
in the codebase that calls `Store.RecordAudit` (the evaluator's
background policy checks, every admin-facing API handler) is unaffected
either way -- forwarding happens in a wrapper around the store itself,
not at each of those call sites. See `internal/siemforward`'s package
doc comment for the full design.

## Splunk HTTP Event Collector (HEC)

The default backend. Configure it with:

- `-siem-hec-url` / `TOPOTRACE_SIEM_HEC_URL` -- your HEC base URL, e.g.
  `https://splunk.example.com:8088`.
- `-siem-hec-token` / `TOPOTRACE_SIEM_HEC_TOKEN` -- the HEC token, sent as
  `Authorization: Splunk <token>`.

Both must be set together, or neither -- leaving both empty disables
SIEM forwarding entirely (the default), with zero overhead and no
forwarder goroutine ever started.

Every recorded audit entry is forwarded as one HEC event: a plain HTTPS
`POST` to `<hec-url>/services/collector/event` with
`Authorization: Splunk <token>` and a JSON body
`{"event": <audit entry>, "sourcetype": "topotrace", "time": <unix-ts>}`.
`<audit entry>` reuses the audit record's own fields (`id`, `actor`,
`action`, `target`, `detail`, `timestamp`) rather than a separate
schema, so what you see in `GET /api/audit` and what lands in Splunk are
the same shape.

Delivery is fire-and-forget with a 5-second timeout, run in its own
goroutine off the request that triggered the audit entry: a slow or
unreachable Splunk instance is logged as a warning and never blocks or
fails the API call that caused the event (see
`internal/siemforward.WrapStore`'s doc comment).

Implemented against Splunk's [published HEC
docs](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector),
stdlib `net/http` only -- no Splunk SDK, matching every other outbound
integration in this project (`internal/oauth`'s OAuth2 client,
`internal/vuln`'s OSV.dev client, `internal/aiquery`'s Anthropic client):
this dev environment has no route to vendor one, and HEC's wire format
is simple enough not to need one anyway. Payload construction is unit
tested against an `httptest.Server` (`internal/siemforward/splunk_test.go`)
-- not verified against a live Splunk instance, since this dev
environment has none to test against.

## Choosing a backend

`-siem-backend` (env `TOPOTRACE_SIEM_BACKEND`) names which forwarder the
URL and token configure. It accepts:

| Name | Product | What the URL is | What the token is |
| --- | --- | --- | --- |
| `splunk-hec` (default) | Splunk HTTP Event Collector | the HEC endpoint, e.g. `https://splunk.example.com:8088/services/collector/event` | the HEC token, sent as `Authorization: Splunk <token>`; required |
| `sumo-http` | Sumo Logic HTTP Logs Source | the collector's source URL, which already carries its own unique key | optional; sent as `X-Sumo-Token` for newer token-authenticated sources, omit for the classic URL-embedded kind |
| `logrhythm-webhook` | LogRhythm Open Collector webhook beat | the beat's listener, e.g. `http://open-collector.example.com:8085/webhook` | optional; sent as a bearer token for a collector behind an authenticating proxy |

The same three names are accepted by `PATCH /api/settings` as
`siem_backend`, and the Settings page's SIEM Forwarding card offers
them in a dropdown, so an operator can switch backends at runtime
without a restart. Splunk is the only one that insists on both a URL
and a token; the other two take a URL alone.

Every backend receives the identical `SIEMEvent` -- one audit entry,
flattened -- so switching backends changes the transport and nothing
about what TopoTrace says.

## Sumo Logic

`internal/siemforward.SumoHTTP` POSTs each event as JSON to a Sumo
Logic [HTTP Logs and Metrics
Source](https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/logs-metrics/).
Sumo's classic HTTP sources embed a unique key in the URL, so the URL
alone is the credential; newer token-authenticated sources also take an
`X-Sumo-Token` header, which is what `-siem-hec-token` supplies when
set. TopoTrace sends `X-Sumo-Category: topotrace/audit` so the events land
under a predictable source category.

## LogRhythm

`internal/siemforward.LogRhythmWebhook` POSTs each event as JSON to a
LogRhythm Open Collector webhook beat (by default a JSON-over-HTTP
listener on port 8085), which normalizes the JSON into LogRhythm's own
schema on the collector side. The beat is unauthenticated on a trusted
network; when it sits behind an authenticating proxy, a token set on
TopoTrace's side is sent as `Authorization: Bearer <token>`.

## What is and is not verified

All three backends are stdlib `net/http` only, written against each
vendor's published ingestion docs, with payload construction unit
tested against an `httptest.Server`
(`internal/siemforward/splunk_test.go`,
`internal/siemforward/backends_test.go`). Backend selection and the
live switch were exercised end to end against a local capture server:
a `PATCH /api/settings` to `sumo-http` took effect immediately and the
next audit entry arrived at the new endpoint.

None of the three has been tested against a live vendor tenant -- this
dev environment has no route to one. Treat the wire formats as
"written from the docs and unit tested," not "verified in production."
