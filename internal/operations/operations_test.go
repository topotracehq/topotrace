/*******************************************************************************
 * @file         operations_test.go
 * @brief        Tests for the TopoTrace operations package.
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
	"path/filepath"
	"testing"
	"time"
	"topotrace/internal/model"
	"topotrace/internal/store/memstore"
)

func TestVerificationRequiresEvidenceAfterExecution(t *testing.T) {
	now := time.Now().UTC()
	a := model.Action{ID: "1", Host: "one", Verb: "restart-service", Arg: "nginx.service", QueuedAt: now.Add(-time.Hour), Delivered: true, DeliveredAt: now.Add(-time.Minute), Status: "ok", ReportedAt: now.Add(-30 * time.Second)}
	facts := map[string]model.Fact{"running_services": {CookedAt: now.Add(-time.Minute), Data: map[string]any{"items": []map[string]any{{"name": "nginx", "active_state": "active"}}}}}
	if v := Verify(a, facts, now); v.State != "executed" {
		t.Fatal(v)
	}
	f := facts["running_services"]
	f.CookedAt = now
	facts["running_services"] = f
	if v := Verify(a, facts, now); v.State != "verified" {
		t.Fatal(v)
	}
	f.Data["items"] = []any{map[string]any{"name": "nginx", "active_state": "inactive"}}
	if v := Verify(a, facts, now); v.State != "failed" {
		t.Fatal(v)
	}
	if v := Verify(a, nil, now.Add(25*time.Hour)); v.State != "timed_out" {
		t.Fatal(v)
	}
}
func TestSelectorAllConditionsAndFreshSoftware(t *testing.T) {
	now := time.Now()
	h := model.Host{Platform: "linux", Tags: []string{"prod", "public"}}
	s := Selector{Platform: "linux", Tag: "prod", Exposure: "internet", MinRisk: 50, Software: "nginx"}
	facts := map[string]model.Fact{"installed_software": {CookedAt: now, Data: map[string]any{"items": []any{map[string]any{"name": "nginx-core"}}}}}
	if !s.Matches(h, facts, 60, now) || s.Matches(h, facts, 40, now) || s.Matches(h, facts, 60, now.Add(25*time.Hour)) {
		t.Fatal("selector ignored risk or freshness")
	}
}
func TestPlansPersistAndGatePilotPromotionAndDelivery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.json")
	st, err := memstore.New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, name := range []string{"one", "two"} {
		if err := st.UpsertHost(ctx, model.Host{Name: name, Platform: "linux"}); err != nil {
			t.Fatal(err)
		}
	}
	p := Plan{ID: "plan", Name: "nginx pilot", Hosts: []string{"one", "two"}, Verb: "restart-service", Arg: "nginx", PilotCount: 1, WindowStart: now.Add(time.Hour), WindowEnd: now.Add(2 * time.Hour)}
	if err := p.Validate(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	if err := Save(ctx, st, PlanKind, p.ID, p); err != nil {
		t.Fatal(err)
	}
	if err := AdvancePlans(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListActions(ctx, "one")
	if len(list) != 0 {
		t.Fatal("dispatched before window")
	}
	if err := AdvancePlans(ctx, st, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	list, _ = st.ListActions(ctx, "one")
	if len(list) != 1 {
		t.Fatal(list)
	}
	a := list[0]
	if ok, _ := DeliveryAllowed(ctx, st, a, now); ok {
		t.Fatal("early delivery")
	}
	if ok, _ := DeliveryAllowed(ctx, st, a, now.Add(time.Hour)); !ok {
		t.Fatal("window delivery blocked")
	}
	if ok, _ := DeliveryAllowed(ctx, st, a, now.Add(2*time.Hour)); ok {
		t.Fatal("late delivery")
	}
	p, _, _ = Load[Plan](ctx, st, PlanKind, p.ID)
	if ok, _ := PilotVerified(ctx, st, p, now); ok {
		t.Fatal("unexecuted pilot verified")
	}
	st.MarkActionDelivered(ctx, a.ID)
	st.RecordActionResult(ctx, a.ID, "ok", "done")
	st.UpsertFact(ctx, model.Fact{Host: "one", Category: "running_services", CookedAt: now.Add(time.Hour), Data: map[string]any{"items": []map[string]any{{"name": "nginx", "active_state": "active"}}}})
	if ok, _ := PilotVerified(ctx, st, p, now.Add(time.Hour)); !ok {
		t.Fatal("fresh pilot was not verified")
	}
	// A verified pilot still does not promote without an explicit decision.
	AdvancePlans(ctx, st, now.Add(time.Hour))
	other, _ := st.ListActions(ctx, "two")
	if len(other) != 0 {
		t.Fatal("implicit promotion")
	}
	p, _, _ = Load[Plan](ctx, st, PlanKind, p.ID)
	p.Promoted = true
	Save(ctx, st, PlanKind, p.ID, p)
	AdvancePlans(ctx, st, now.Add(time.Hour))
	AdvancePlans(ctx, st, now.Add(time.Hour))
	other, _ = st.ListActions(ctx, "two")
	if len(other) != 1 {
		t.Fatal("rollout duplicated or absent", other)
	}
	st, err = memstore.New(path)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ = Load[Plan](ctx, st, PlanKind, p.ID)
	p.Cancelled = true
	Save(ctx, st, PlanKind, p.ID, p)
	if ok, _ := DeliveryAllowed(ctx, st, other[0], now.Add(time.Hour)); ok {
		t.Fatal("cancelled action delivered")
	}
}
func TestExceptionExpiresAndUnsupportedChangesRejected(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	now := time.Now()
	st.UpsertHost(ctx, model.Host{Name: "one", Platform: "linux"})
	Save(ctx, st, ExceptionKind, "finding", Exception{ID: "finding", ExpiresAt: now.Add(time.Hour)})
	if _, active, _ := ExceptionFor(ctx, st, "finding", now); !active {
		t.Fatal("exception inactive")
	}
	if _, active, _ := ExceptionFor(ctx, st, "finding", now.Add(time.Hour)); active {
		t.Fatal("exception did not expire")
	}
	p := Plan{Name: "updates", Hosts: []string{"one"}, Verb: "apply-updates", PilotCount: 1, WindowStart: now, WindowEnd: now.Add(time.Hour)}
	if p.Validate(ctx, st, now) == nil {
		t.Fatal("unsupported updates accepted")
	}
}
