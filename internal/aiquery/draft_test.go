/*******************************************************************************
 * @file         draft_test.go
 * @brief        Tests for the Muster aiquery package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package aiquery

import (
	"context"
	"testing"
)

func TestHeuristicDraft(t *testing.T) {
	cases := []struct {
		desc              string
		kind, group, verb string
		threshold         int
		approval          bool
	}{
		{"flag any prod host with a posture score below 80", "score_below", "prod", "", 80, false},
		{"alert when a host has known vulnerabilities and apply updates after I approve", "vulnerabilities_found", "", "apply-updates", 0, true},
		{"hosts that haven't reported in 24 hours", "stale", "", "", 0, false},
		{"eng machines missing firewall_av_status, restart the ufw service", "category_missing", "eng", "restart-service", 0, false},
	}
	for _, c := range cases {
		d, err := DraftPolicy(context.Background(), Config{}, c.desc)
		if err != nil {
			t.Fatalf("%q: %v", c.desc, err)
		}
		if d.Source != "heuristic" || d.Kind != c.kind || d.Group != c.group || d.AutoRemediate != c.verb || d.RequireApproval != c.approval {
			t.Errorf("%q: got %+v", c.desc, d)
		}
		if c.threshold != 0 && d.Threshold != c.threshold {
			t.Errorf("%q: threshold %d", c.desc, d.Threshold)
		}
		if err := Validate(d); err != nil {
			t.Errorf("%q: draft should validate: %v", c.desc, err)
		}
	}
	if _, err := DraftPolicy(context.Background(), Config{}, "  "); err == nil {
		t.Fatal("empty description should error")
	}
	if err := Validate(PolicyDraft{Name: "x", Kind: "score_below"}); err == nil {
		t.Fatal("score_below without threshold should fail validation")
	}
}
