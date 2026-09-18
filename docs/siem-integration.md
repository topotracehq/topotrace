# SIEM integration

Muster can forward its own audit trail to a real SIEM, so events that
already get recorded to `GET /api/audit` (policy violations,
remediation, Ask Muster queries, enrollment/key management, OAuth
logins, and every other authenticated write) also reach an operator's
existing security tooling -- not just Muster's own dashboard.

This is built on a small `Forwarder` interface
(`internal/siemforward.Forwarder`, `Send(ctx, event) error`) so more
backends can be added later without touching any call site: every place
in the codebase that calls `Store.RecordAudit` (the evaluator's
background policy checks, every admin-facing API handler) is unaffected
either way -- forwarding happens in a wrapper around the store itself,
not at each of those call sites. See `internal/siemforward`'s package
doc comment for the full design.

## Splunk HTTP Event Collector (HEC) -- available now

The one real backend implemented so far. Configure it with:

- `-siem-hec-url` / `MUSTER_SIEM_HEC_URL` -- your HEC base URL, e.g.
  `https://splunk.example.com:8088`.
- `-siem-hec-token` / `MUSTER_SIEM_HEC_TOKEN` -- the HEC token, sent as
  `Authorization: Splunk <token>`.

Both must be set together, or neither -- leaving both empty disables
SIEM forwarding entirely (the default), with zero overhead and no
forwarder goroutine ever started.

Every recorded audit entry is forwarded as one HEC event: a plain HTTPS
`POST` to `<hec-url>/services/collector/event` with
`Authorization: Splunk <token>` and a JSON body
`{"event": <audit entry>, "sourcetype": "muster", "time": <unix-ts>}`.
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

## LogRhythm and Sumo Logic -- documented, not implemented

Both are natural second backends for `Forwarder`: LogRhythm's HTTP Log
& Metrics Collector and Sumo Logic's HTTP Source both accept
HEC-style/similar plain-HTTPS-POST-with-a-token ingestion, close enough
to Splunk HEC's shape that adding either should mean a new
`internal/siemforward/<backend>.go` implementing `Forwarder` -- nothing
else in the codebase would need to change, per the whole point of the
`Forwarder` seam. Neither is implemented this round; only Splunk HEC is
real today.
