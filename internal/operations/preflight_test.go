/*******************************************************************************
 * @file         preflight_test.go
 * @brief        Tests for the Muster operations package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package operations

import (
	"context"
	"muster/internal/model"
	"muster/internal/store/memstore"
	"testing"
	"time"
)

func TestPreflightRechecksAtDispatchAndDetectsOverlap(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st, _ := memstore.New("")
	st.UpsertHost(ctx, model.Host{Name: "one", Platform: "linux", LastCooked: now})
	put := func(at time.Time) {
		st.UpsertFact(ctx, model.Fact{Host: "one", Category: "running_services", CookedAt: at, Data: map[string]any{"items": []map[string]any{{"name": "nginx.service", "active_state": "active"}}}})
	}
	put(now)
	p := Plan{ID: "p", Name: "restart", Hosts: []string{"one"}, Verb: "restart-service", Arg: "nginx", PilotCount: 1, WindowStart: now, WindowEnd: now.Add(time.Hour), RequirePreflight: true, BackupConfirmed: true, RollbackInstructions: "Restore the service configuration from the verified backup and validate health."}
	check, err := Preflight(ctx, st, p, now)
	if err != nil || !check.Ready {
		t.Fatal(check, err)
	}
	other := p
	other.ID = "other"
	Save(ctx, st, PlanKind, other.ID, other)
	check, err = Preflight(ctx, st, p, now)
	if err != nil || check.Ready {
		t.Fatal("overlap should block", check, err)
	}
	st.DeleteDocument(ctx, PlanKind, other.ID)
	Save(ctx, st, PlanKind, p.ID, p)
	put(now.Add(-48 * time.Hour))
	if err := AdvancePlans(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	actions, _ := st.ListActions(ctx, "one")
	if len(actions) != 0 {
		t.Fatal("stale evidence dispatched an action")
	}
	put(now)
	if err := AdvancePlans(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	actions, _ = st.ListActions(ctx, "one")
	if len(actions) != 1 {
		t.Fatal("ready pilot did not dispatch", actions)
	}
}
