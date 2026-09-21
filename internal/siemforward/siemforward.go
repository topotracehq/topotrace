/*******************************************************************************
 * @file         siemforward.go
 * @brief        Package siemforward forwards Muster's audit trail to a real SIEM, so events that already get recorded via store.Store.RecordAudit (policy violations, remediation, Ask Muster queries, enrollment/key management, OAuth logins, ...) also rea...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package siemforward forwards Muster's audit trail to a real SIEM, so
// events that already get recorded via store.Store.RecordAudit (policy
// violations, remediation, Ask Muster queries, enrollment/key
// management, OAuth logins, ...) also reach an operator's existing
// security tooling, not just Muster's own /api/audit.
//
// Forwarder is the seam that keeps this backend-agnostic: SplunkHEC is
// the one real implementation this round (stdlib net/http only, no SDK
// -- this dev environment can't vendor one anyway, and Splunk's HTTP
// Event Collector wire format is simple enough not to need one). A
// LogRhythm or Sumo Logic backend can be added later as another
// Forwarder without touching WrapStore or any call site -- see
// docs/siem-integration.md.
package siemforward

import "context"

// SIEMEvent is what gets forwarded for one audit-log entry.
// Deliberately shaped like model.AuditEntry (see WrapStore's
// conversion) rather than inventing a separate schema -- this package
// doesn't import internal/model itself, so it stays usable for
// anything else that might want to forward a SIEMEvent later, not just
// the audit-log wrapper.
type SIEMEvent struct {
	ID        string `json:"id,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Action    string `json:"action,omitempty"`
	Target    string `json:"target,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Timestamp int64  `json:"timestamp"` // Unix seconds
}

// Forwarder sends one SIEMEvent to a SIEM backend. Implementations
// should apply their own deadline via ctx rather than blocking
// indefinitely -- every caller in this package fires these off in a
// goroutine with a short timeout (see WrapStore) precisely so a slow or
// unreachable SIEM can never hold up the request that triggered the
// event.
type Forwarder interface {
	Send(ctx context.Context, event SIEMEvent) error
}
