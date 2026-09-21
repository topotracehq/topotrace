/*******************************************************************************
 * @file         ueba_test.go
 * @brief        Tests for the Muster ueba package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package ueba

import (
	"fmt"
	"testing"
	"time"

	"muster/internal/model"
)

func TestAnalyze(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, loc) // a Wednesday
	var entries []model.AuditEntry
	id := 0
	add := func(actor, action, detail string, at time.Time) {
		id++
		entries = append(entries, model.AuditEntry{ID: fmt.Sprint(id), Actor: actor, Action: action, Detail: detail, CreatedAt: at})
	}
	// alice: long-standing, one off-hours write, an admin key at 3am
	add("alice", "create-policy", "x", now.Add(-30*24*time.Hour))
	add("alice", "create-key", `key "ops-admin" role admin`, now.Add(-9*time.Hour)) // 03:00
	// bob: brand new, 12 writes in 5 minutes during the day, 3 deletes
	for i := 0; i < 12; i++ {
		add("bob", "delete-policy", "p", now.Add(-time.Hour+time.Duration(i)*20*time.Second))
	}
	// system noise must be ignored
	for i := 0; i < 50; i++ {
		add("system", "policy-violation", "z", now.Add(-time.Duration(i)*time.Hour))
	}
	// carol: settings change
	add("carol", "settings_updated", "siem forwarding configured", now.Add(-2*time.Hour))
	add("carol", "ask-muster", "q", now.Add(-40*24*time.Hour))

	sig := Analyze(entries, Options{Now: now, Location: loc})
	kinds := map[string][]Signal{}
	for _, s := range sig {
		kinds[s.Kind] = append(kinds[s.Kind], s)
	}
	if len(kinds["new-admin-key"]) != 1 || kinds["new-admin-key"][0].Actor != "alice" {
		t.Fatalf("new-admin-key: %+v", kinds["new-admin-key"])
	}
	if len(kinds["off-hours"]) != 1 || kinds["off-hours"][0].Actor != "alice" {
		t.Fatalf("off-hours: %+v", kinds["off-hours"])
	}
	if len(kinds["burst"]) != 1 || kinds["burst"][0].Actor != "bob" {
		t.Fatalf("burst: %+v", kinds["burst"])
	}
	if len(kinds["mass-delete"]) != 1 || kinds["mass-delete"][0].Count != 12 {
		t.Fatalf("mass-delete: %+v", kinds["mass-delete"])
	}
	if len(kinds["new-actor"]) != 1 || kinds["new-actor"][0].Actor != "bob" {
		t.Fatalf("new-actor: %+v", kinds["new-actor"])
	}
	if len(kinds["settings-change"]) != 1 || kinds["settings-change"][0].Actor != "carol" {
		t.Fatalf("settings-change: %+v", kinds["settings-change"])
	}
	if sig[0].Severity != "high" {
		t.Fatalf("most severe first: %+v", sig[0])
	}
}
