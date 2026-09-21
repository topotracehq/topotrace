/*******************************************************************************
 * @file         risk_test.go
 * @brief        Tests for the Muster risk package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package risk

import (
	"testing"

	"muster/internal/allowlist"
	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/vuln"
)

func TestCleanHostIsLowRisk(t *testing.T) {
	r := Compute(compliance.Input{Host: model.Host{Name: "h"}, Posture: policy.PostureResult{Score: 100}})
	if r.Score != 0 || r.Level != "low" || r.Criticality != "medium" || r.Exposure != "internal" {
		t.Fatalf("%+v", r)
	}
}

func TestMultipliersAndCap(t *testing.T) {
	in := compliance.Input{
		Host:               model.Host{Name: "db", Tags: []string{"criticality:critical", "public"}},
		Posture:            policy.PostureResult{Score: 40},
		Stale:              true,
		VulnFindings:       []vuln.Finding{{Severity: "critical"}, {Severity: "high"}, {Severity: "high"}},
		ShadowAIViolations: []allowlist.Violation{{}, {}, {}, {}},
	}
	r := Compute(in)
	if r.Criticality != "critical" || r.Exposure != "internet" || r.Multiplier != 2.0 {
		t.Fatalf("%+v", r)
	}
	if r.Score != 100 || r.Level != "critical" {
		t.Fatalf("expected capped critical score, got %+v", r)
	}
	// same signals on a low-criticality internal box score far lower
	in.Host.Tags = []string{"criticality:low"}
	r2 := Compute(in)
	if r2.Score >= r.Score || r2.Multiplier != 0.7 {
		t.Fatalf("expected lower score for low criticality, got %+v", r2)
	}
}

func TestRank(t *testing.T) {
	rs := []Result{{Host: "b", Score: 10}, {Host: "a", Score: 10}, {Host: "c", Score: 90}}
	Rank(rs)
	if rs[0].Host != "c" || rs[1].Host != "a" || rs[2].Host != "b" {
		t.Fatalf("%+v", rs)
	}
}
