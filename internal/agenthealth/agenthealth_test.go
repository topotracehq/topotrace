/*******************************************************************************
 * @file         agenthealth_test.go
 * @brief        Tests for the Muster agenthealth package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package agenthealth

import (
	"context"
	"testing"
	"time"

	"muster/internal/store/memstore"
)

func TestCheckinCadenceAndStates(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := Checkin(ctx, st, "h1", "tcp", 3, t0.Add(time.Duration(i)*30*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := Get(ctx, st, "h1", t0.Add(4*30*time.Minute+5*time.Minute))
	if s.State != "healthy" || s.Checkins != 5 || s.ExpectedEverySec != 1800 || s.Path != "tcp" {
		t.Fatalf("%+v", s)
	}
	s, _ = Get(ctx, st, "h1", t0.Add(4*30*time.Minute+90*time.Minute))
	if s.State != "late" || s.LateBySec != 1800 {
		t.Fatalf("late: %+v", s)
	}
	s, _ = Get(ctx, st, "h1", t0.Add(3*24*time.Hour))
	if s.State != "missing" {
		t.Fatalf("missing: %+v", s)
	}
	Failure(ctx, st, "h1", "unauthorized upload", t0.Add(4*30*time.Minute+10*time.Minute))
	s, _ = Get(ctx, st, "h1", t0.Add(4*30*time.Minute+12*time.Minute))
	if s.State != "failing" || s.Failures != 1 {
		t.Fatalf("failing: %+v", s)
	}
	Failure(ctx, st, "ghost", "unauthorized upload", t0)
	all, _ := All(ctx, st, t0.Add(4*30*time.Minute+12*time.Minute))
	if len(all) != 2 || all[0].State != "failing" {
		t.Fatalf("all: %+v", all)
	}
	if s, _ := Get(ctx, st, "nobody", t0); s.State != "never" {
		t.Fatalf("never: %+v", s)
	}
}
