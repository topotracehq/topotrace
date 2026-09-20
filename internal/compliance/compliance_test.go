/*******************************************************************************
 * @file         compliance_test.go
 * @brief        Tests for the Muster compliance package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package compliance

import (
	"testing"

	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/vuln"
)

func TestFrameworksArePluggable(t *testing.T) {
	if len(Frameworks) != 3 {
		t.Fatalf("expected 3 frameworks, got %d", len(Frameworks))
	}
	if f, ok := ByID("HIPAA"); !ok || f.ID != "hipaa" {
		t.Fatalf("ByID should be case-insensitive: %+v %v", f, ok)
	}
	if _, ok := ByID("pci"); ok {
		t.Fatal("unknown framework should not resolve")
	}
	clean := Input{Host: model.Host{Name: "h", Platform: "linux"}, Posture: policy.PostureResult{Score: 100},
		Facts: map[string]model.Fact{
			"system_summary":     {Data: map[string]any{}},
			"installed_software": {Data: map[string]any{}},
			"firewall_av_status": {Data: map[string]any{"ufw_status": "active"}},
		}}
	for _, r := range EvaluateAll(clean) {
		if r.Score != 100 {
			t.Fatalf("clean host should score 100 on %s: %+v", r.FrameworkID, r)
		}
	}
	bad := clean
	bad.Facts = map[string]model.Fact{"firewall_av_status": {Data: map[string]any{"ufw_status": "inactive"}}, "patch_update_status": {Data: map[string]any{"count": 7}}}
	bad.VulnFindings = []vuln.Finding{{Severity: "high"}}
	h := HIPAA.Evaluate(bad)
	if h.Score == 100 {
		t.Fatalf("hipaa should fail checks: %+v", h)
	}
	failed := 0
	for _, c := range h.Checks {
		if !c.Pass {
			failed++
		}
	}
	if failed != 4 { // malware, patching, firewall, audit controls (missing inventory facts)
		t.Fatalf("expected 4 failed hipaa checks, got %d: %+v", failed, h.Checks)
	}
	n := NIST80053.Evaluate(bad)
	if n.Score != 66 { // 4 of 6 pass: SI-2 and SC-7 fail
		t.Fatalf("expected nist score 66, got %+v", n)
	}
}

func TestFirewallStateWindows(t *testing.T) {
	in := Input{Host: model.Host{Platform: "windows"}, Facts: map[string]model.Fact{"firewall_av_status": {Data: map[string]any{"domain_enabled": "True", "public_enabled": "False"}}}}
	if on, known := firewallState(in); !known || on {
		t.Fatalf("one disabled profile should read as off: on=%v known=%v", on, known)
	}
	in.Facts["firewall_av_status"] = model.Fact{Data: map[string]any{"domain_enabled": "True"}}
	if on, known := firewallState(in); !known || !on {
		t.Fatalf("all enabled should read as on: on=%v known=%v", on, known)
	}
	if _, known := firewallState(Input{Host: model.Host{Platform: "darwin"}, Facts: map[string]model.Fact{}}); known {
		t.Fatal("no category should be unknown")
	}
}
