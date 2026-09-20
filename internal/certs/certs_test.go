/*******************************************************************************
 * @file         certs_test.go
 * @brief        Tests for the Muster certs package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package certs

import (
	"testing"
	"time"
)

func TestFromFact(t *testing.T) {
	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	items := []any{
		map[string]any{"id": "a", "subject": "CN=ok", "not_after": "2027-09-18T00:00:00Z"},
		map[string]any{"id": "b", "subject": "CN=soon", "not_after": "2026-10-01T00:00:00Z"},
		map[string]any{"id": "c", "subject": "CN=dead", "not_after": "2026-01-01T00:00:00Z"},
		map[string]any{"id": "d", "subject": "CN=weird", "not_after": "yesterday"},
	}
	cs := FromFact(items, now)
	if len(cs) != 4 || cs[0].State != "expired" || cs[1].State != "expiring" || cs[2].State != "unknown" || cs[3].State != "ok" {
		t.Fatalf("%+v", cs)
	}
	if cs[1].DaysLeft != 13 {
		t.Fatalf("days left: %d", cs[1].DaysLeft)
	}
	if len(Problems(cs)) != 2 {
		t.Fatal("expected 2 problems")
	}
}
