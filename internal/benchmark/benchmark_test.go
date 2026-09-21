/*******************************************************************************
 * @file         benchmark_test.go
 * @brief        Tests for the Muster benchmark package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package benchmark

import "testing"

func TestCompareDirections(t *testing.T) {
	ms := Compare(Fleet{AvgPosture: 83, AvgCompliance: 60, PctWithVulns: 40, PctStale: 9, PctShadowAI: 5, MTTRHours: 100, MTTRMeasured: true})
	byKey := map[string]Metric{}
	for _, m := range ms {
		byKey[m.Key] = m
	}
	if !byKey["avg_posture"].Better || byKey["avg_compliance"].Better {
		t.Fatalf("posture should be better, compliance worse: %+v %+v", byKey["avg_posture"], byKey["avg_compliance"])
	}
	if byKey["pct_with_vulns"].Better || !byKey["pct_shadow_ai"].Better {
		t.Fatalf("vulns worse, shadow ai better: %+v %+v", byKey["pct_with_vulns"], byKey["pct_shadow_ai"])
	}
	if !byKey["pct_stale"].Better || byKey["pct_stale"].Summary != "level with baseline" {
		t.Fatalf("stale: %+v", byKey["pct_stale"])
	}
	if !byKey["mttr_hours"].Better || byKey["mttr_hours"].Summary != "better than baseline by 5.3 days" {
		t.Fatalf("mttr: %+v", byKey["mttr_hours"])
	}
	if len(Compare(Fleet{})) != 5 {
		t.Fatal("unmeasured MTTR should be omitted")
	}
}
