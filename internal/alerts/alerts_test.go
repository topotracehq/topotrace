/*******************************************************************************
 * @file         alerts_test.go
 * @brief        Tests for the Muster alerts package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package alerts

import (
	"context"
	"testing"
	"time"

	"muster/internal/store/memstore"
)

func TestObserveDedupsAndRealerts(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s := State{Open: map[string]Violation{}}
	key := PolicyKey("r1", "h1")
	if d := s.Observe(key, "policy", "r1", "Rule", "h1", "stale", now); d != Announce {
		t.Fatal("first sighting should announce")
	}
	if d := s.Observe(key, "policy", "r1", "Rule", "h1", "stale", now.Add(5*time.Minute)); d != Quiet {
		t.Fatal("second sighting minutes later should be quiet")
	}
	if s.Open[key].Occurrences != 2 {
		t.Fatalf("occurrences: %+v", s.Open[key])
	}
	if d := s.Observe(key, "policy", "r1", "Rule", "h1", "stale", now.Add(RealertAfter+time.Minute)); d != Announce {
		t.Fatal("after RealertAfter it should announce again")
	}
	if !s.Snooze(key, "master", 48*time.Hour, now.Add(RealertAfter+time.Minute)) {
		t.Fatal("snooze should find the violation")
	}
	if d := s.Observe(key, "policy", "r1", "Rule", "h1", "stale", now.Add(2*RealertAfter+time.Minute)); d != Quiet {
		t.Fatal("snoozed violation should stay quiet past RealertAfter")
	}
	if !s.Unsnooze(key) || s.Snooze("nope", "x", time.Hour, now) {
		t.Fatal("unsnooze/snooze bookkeeping")
	}
	closed := s.Resolve(map[string]bool{})
	if len(closed) != 1 || closed[0].Key != key || len(s.Open) != 0 {
		t.Fatalf("resolve: %+v open=%d", closed, len(s.Open))
	}
}

func TestStateRoundTripAndApprovals(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	s, err := Load(ctx, st)
	if err != nil || len(s.Open) != 0 {
		t.Fatalf("empty load: %+v %v", s, err)
	}
	s.Observe(SoftwareKey("Ban vsftpd", "h1", "vsftpd"), "software", "", "Ban vsftpd", "h1", "denied", time.Now())
	if err := Save(ctx, st, s); err != nil {
		t.Fatal(err)
	}
	s2, _ := Load(ctx, st)
	if len(s2.List()) != 1 || s2.List()[0].Kind != "software" {
		t.Fatalf("round trip: %+v", s2)
	}

	created, err := ProposeApproval(ctx, st, Approval{Host: "h1", RuleID: "r1", RuleName: "Rule", Verb: "restart-service", Arg: "nginx", Reason: "score below 80"})
	if err != nil || !created {
		t.Fatalf("propose: created=%v err=%v", created, err)
	}
	created, _ = ProposeApproval(ctx, st, Approval{Host: "h1", RuleID: "r1", RuleName: "Rule", Verb: "restart-service"})
	if created {
		t.Fatal("duplicate proposal should not create a second approval")
	}
	list, _ := ListApprovals(ctx, st)
	if len(list) != 1 || list[0].ID != "r1|h1" || list[0].Arg != "nginx" {
		t.Fatalf("list: %+v", list)
	}
	if a, ok, _ := GetApproval(ctx, st, "r1|h1"); !ok || a.Verb != "restart-service" {
		t.Fatalf("get: %+v %v", a, ok)
	}
	if err := RemoveApproval(ctx, st, "r1|h1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := ListApprovals(ctx, st); len(list) != 0 {
		t.Fatal("approval should be gone")
	}
}
