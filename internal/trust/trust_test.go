/*******************************************************************************
 * @file         trust_test.go
 * @brief        Tests for the Muster trust package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package trust

import (
	"testing"
	"time"

	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/vuln"
)

func TestEvaluate(t *testing.T) {
	now := time.Now()
	clean := compliance.Input{Host: model.Host{Name: "h"}, Posture: policy.PostureResult{Score: 100}}
	v := Evaluate(clean, 0, now)
	if v.Score != 100 || v.Level != "trusted" || !v.Allow || v.MinScore != ConditionalAt {
		t.Fatalf("%+v", v)
	}
	bad := compliance.Input{Host: model.Host{Name: "h", Tags: []string{"public", "criticality:critical"}}, Posture: policy.PostureResult{Score: 30}, Stale: true,
		VulnFindings: []vuln.Finding{{Severity: "critical"}, {Severity: "critical"}}}
	v = Evaluate(bad, 90, now)
	if v.Level != "untrusted" || v.Allow || len(v.Reasons) < 2 {
		t.Fatalf("%+v", v)
	}
	staleClean := clean
	staleClean.Stale = true
	v = Evaluate(staleClean, 0, now)
	if v.Level == "trusted" {
		t.Fatal("a stale host must never be trusted outright")
	}
}
