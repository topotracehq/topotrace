/*******************************************************************************
 * @file         signals.go
 * @brief        Package signals gathers, for one host, everything Muster's higher-level evaluations need -- facts by category, staleness, posture score, vulnerability findings, software allow/deny violations, Shadow AI detections -- into one compliance.Input.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package signals gathers, for one host, everything Muster's higher-level
// evaluations need -- facts by category, staleness, posture score,
// vulnerability findings, software allow/deny violations, Shadow AI
// detections -- into one compliance.Input. It exists so internal/api
// (per-request views), internal/evaluator (the background loop), and
// anything else that scores a host all compute those signals the exact
// same way, from one function, instead of each re-deriving them.
package signals

import (
	"context"
	"time"

	"muster/internal/allowlist"
	"muster/internal/browserext"
	"muster/internal/certs"
	"muster/internal/compliance"
	"muster/internal/eol"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/scanner"
	"muster/internal/store"
	"muster/internal/vuln"
)

// FactsByCategory loads a host's facts keyed by category.
func FactsByCategory(ctx context.Context, st store.Store, host string) (map[string]model.Fact, error) {
	facts, err := st.ListFacts(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		out[f.Category] = f
	}
	return out, nil
}

// Gather computes a compliance.Input for host from its stored facts.
// softwareRules is the full rule list (group scoping happens here);
// feed may be nil (see vuln.CheckWithFeed).
func Gather(ctx context.Context, st store.Store, host model.Host, softwareRules []model.SoftwareRule, feed *vuln.Feed) (compliance.Input, error) {
	byCategory, err := FactsByCategory(ctx, st, host.Name)
	if err != nil {
		return compliance.Input{}, err
	}
	return FromFacts(host, byCategory, softwareRules, feed, time.Now().UTC()), nil
}

// FromFacts is Gather without the Store round-trip, for callers that
// already hold the host's facts (the evaluator loads them once per
// host and reuses them across every rule).
func FromFacts(host model.Host, byCategory map[string]model.Fact, softwareRules []model.SoftwareRule, feed *vuln.Feed, now time.Time) compliance.Input {
	stale := policy.IsStale(host.LastCooked, now)
	posture := policy.ComputePostureAt(host.Platform, byCategory, stale, now)

	var inScope []model.SoftwareRule
	for _, rule := range softwareRules {
		if rule.Group == "" || rule.Group == host.Group {
			inScope = append(inScope, rule)
		}
	}
	in := compliance.Input{Host: host, Facts: byCategory, Stale: stale, Posture: posture}
	if sw, ok := byCategory["installed_software"]; ok {
		in.VulnFindings = vuln.CheckWithFeed(sw.Data["items"], feed)
		in.SoftwareViolations = allowlist.Evaluate(sw.Data["items"], inScope)
		in.ShadowAIViolations = allowlist.EvaluateShadowAI(sw.Data["items"], inScope)
	}
	if sf, ok := byCategory["scanner_findings"]; ok {
		in.VulnFindings = append(in.VulnFindings, scanner.FromFact(sf.Data["items"])...)
	}
	if ext, ok := byCategory["browser_extensions"]; ok {
		in.BrowserExtensions = browserext.Evaluate(browserext.FromFact(ext.Data["items"]))
	}
	if sum, ok := byCategory["system_summary"]; ok {
		in.OSLifecycle = eol.Check(sum.Data, now)
	} else {
		in.OSLifecycle = eol.Status{State: "unknown", Detail: "no system_summary reported"}
	}
	if tc, ok := byCategory["tls_certificates"]; ok {
		in.Certificates = certs.FromFact(tc.Data["items"], now)
	}
	return in
}
