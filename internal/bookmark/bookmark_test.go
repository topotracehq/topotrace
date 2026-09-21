/*******************************************************************************
 * @file         bookmark_test.go
 * @brief        Tests for the Muster bookmark package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package bookmark

import (
	"context"
	"testing"

	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/store/memstore"
	"muster/internal/vuln"
)

func TestSnapshotSaveCompare(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	then := Snapshot([]compliance.Input{
		{Host: model.Host{Name: "a", Group: "prod"}, Posture: policy.PostureResult{Score: 60}, VulnFindings: []vuln.Finding{{Severity: "high"}}},
		{Host: model.Host{Name: "b"}, Posture: policy.PostureResult{Score: 100}, Stale: true},
	}, 2, 3)
	saved, err := Save(ctx, st, then, "", "master")
	if err != nil || saved.ID != "1" || saved.Name == "" {
		t.Fatalf("save: %+v %v", saved, err)
	}
	if _, err := Save(ctx, st, then, "second", "master"); err != nil {
		t.Fatal(err)
	}
	list, _ := List(ctx, st)
	if len(list) != 2 || list[0].Name != "second" {
		t.Fatalf("list: %+v", list)
	}
	now := Snapshot([]compliance.Input{
		{Host: model.Host{Name: "a", Group: "prod"}, Posture: policy.PostureResult{Score: 90}},
		{Host: model.Host{Name: "c"}, Posture: policy.PostureResult{Score: 80}},
	}, 3, 3)
	d := Compare(saved, now)
	kinds := map[string]int{}
	for _, c := range d.Changes {
		kinds[c.Kind]++
	}
	if kinds["host-removed"] != 1 || kinds["host-added"] != 1 || kinds["posture"] != 1 || kinds["vulns"] != 1 || kinds["rules"] != 1 {
		t.Fatalf("changes: %+v", d.Changes)
	}
	if d.Better < 3 || d.Worse != 0 {
		t.Fatalf("better/worse: %d/%d %+v", d.Better, d.Worse, d.Changes)
	}
	if err := Delete(ctx, st, "1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := Get(ctx, st, "1"); ok {
		t.Fatal("deleted bookmark should be gone")
	}
}
