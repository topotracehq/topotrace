/*******************************************************************************
 * @file         operations_test.go
 * @brief        Tests for the TopoTrace evaluator package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package evaluator

import (
	"context"
	"testing"
	"time"
	"topotrace/internal/alerts"
	"topotrace/internal/model"
	"topotrace/internal/operations"
	"topotrace/internal/store/memstore"
	"topotrace/internal/webhook"
)

func TestDynamicPolicyExceptionExpiryAndOwnershipEscalation(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	now := time.Now().UTC()
	for _, h := range []model.Host{{Name: "linux", Platform: "linux", LastCooked: now.Add(-25 * time.Hour)}, {Name: "windows", Platform: "windows", LastCooked: now.Add(-25 * time.Hour)}} {
		if err := st.UpsertHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	g := operations.DynamicGroup{ID: "linux", Name: "Linux", Selector: operations.Selector{Platform: "linux"}}
	operations.Save(ctx, st, operations.GroupKind, g.ID, g)
	rule, err := st.CreateRule(ctx, model.Rule{Name: "stale Linux", Group: "dynamic:linux", Kind: "stale", AutoRemediate: "restart-service", AutoRemediateArg: "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	key := alerts.PolicyKey(rule.ID, "linux")
	ex := operations.Exception{ID: key, Host: "linux", Reason: "maintenance", ExpiresAt: now.Add(time.Hour)}
	operations.Save(ctx, st, operations.ExceptionKind, key, ex)
	due := now.Add(-time.Hour)
	operations.Save(ctx, st, operations.AssignmentKind, "host:linux", operations.Assignment{ID: "host:linux", Host: "linux", Owner: "Ops", DueAt: &due, EscalateTo: "Team lead"})
	e := Evaluator{Store: st}
	e.runOnce(ctx)
	actions, _ := st.ListActions(ctx, "linux")
	if len(actions) != 0 {
		t.Fatal("exception did not suppress remediation")
	}
	ex.ExpiresAt = now.Add(-time.Minute)
	operations.Save(ctx, st, operations.ExceptionKind, key, ex)
	e.runOnce(ctx)
	e.runOnce(ctx)
	actions, _ = st.ListActions(ctx, "linux")
	if len(actions) != 1 {
		t.Fatal("expiry should queue once", actions)
	}
	actions, _ = st.ListActions(ctx, "windows")
	if len(actions) != 0 {
		t.Fatal("dynamic policy targeted Windows")
	}
	audit, _ := st.ListAudit(ctx, "linux", 100)
	count := 0
	for _, a := range audit {
		if a.Action == "work-overdue" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("wanted one escalation, got %d", count)
	}
}

func TestEscalationDelayAndRepeat(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	now := time.Now().UTC()
	st.UpsertHost(ctx, model.Host{Name: "one", Platform: "linux", LastCooked: now})
	due := now.Add(-time.Hour)
	a := operations.Assignment{ID: "host:one", Host: "one", Owner: "Ops", DueAt: &due, EscalateTo: "Lead"}
	operations.Save(ctx, st, operations.AssignmentKind, a.ID, a)
	operations.Save(ctx, st, webhook.PreferencesKind, "global", webhook.Preferences{Timezone: "UTC", EscalationDelayHours: 2, EscalationRepeatHours: 4})
	e := Evaluator{Store: st}
	count := func() int {
		rows, _ := st.ListAudit(ctx, "one", 0)
		n := 0
		for _, v := range rows {
			if v.Action == "work-overdue" {
				n++
			}
		}
		return n
	}
	e.escalateOverdue(ctx, now)
	if count() != 0 {
		t.Fatal("escalated before grace period")
	}
	e.escalateOverdue(ctx, now.Add(2*time.Hour))
	if count() != 1 {
		t.Fatal("did not escalate after grace period")
	}
	e.escalateOverdue(ctx, now.Add(3*time.Hour))
	if count() != 1 {
		t.Fatal("repeat occurred too early")
	}
	e.escalateOverdue(ctx, now.Add(6*time.Hour))
	if count() != 2 {
		t.Fatal("repeat escalation missing")
	}
}
