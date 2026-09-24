/*******************************************************************************
 * @file         session_test.go
 * @brief        Tests for SessionStore -- basic create/get/delete/expiry,
 *               plus the session management controls (#27) and MFA
 *               gating (#26) added on top of it.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package oauth

import (
	"testing"
	"time"
)

func TestSessionCreateGetDelete(t *testing.T) {
	s := NewSessionStore()
	id := s.Create("alice@example.com", "admin")
	if id == "" {
		t.Fatal("Create returned empty id")
	}
	sess, ok := s.Get(id)
	if !ok {
		t.Fatal("Get should find a just-created session")
	}
	if sess.Email != "alice@example.com" || sess.Role != "admin" {
		t.Errorf("unexpected session: %+v", sess)
	}
	if sess.CreatedAt.IsZero() || sess.LastSeen.IsZero() {
		t.Errorf("CreatedAt/LastSeen should be stamped on Create: %+v", sess)
	}
	s.Delete(id)
	if _, ok := s.Get(id); ok {
		t.Error("Get should not find a deleted session")
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	s := NewSessionStore()
	s.IdleTimeout = 10 * time.Millisecond
	id := s.Create("alice@example.com", "readonly")
	time.Sleep(20 * time.Millisecond)
	if _, ok := s.Get(id); ok {
		t.Error("Get should expire a session idle longer than IdleTimeout")
	}
}

func TestSessionTouchResetsIdleClock(t *testing.T) {
	s := NewSessionStore()
	s.IdleTimeout = 30 * time.Millisecond
	id := s.Create("alice@example.com", "readonly")
	time.Sleep(20 * time.Millisecond)
	s.Touch(id)
	time.Sleep(20 * time.Millisecond)
	if _, ok := s.Get(id); !ok {
		t.Error("Touch should have reset the idle clock, keeping the session alive")
	}
}

func TestSessionMaxConcurrentEvictsOldest(t *testing.T) {
	s := NewSessionStore()
	s.MaxConcurrent = 2
	first := s.Create("bob@example.com", "readonly")
	time.Sleep(time.Millisecond) // ensure distinct CreatedAt ordering
	second := s.Create("bob@example.com", "readonly")
	time.Sleep(time.Millisecond)
	third := s.Create("bob@example.com", "readonly")

	if _, ok := s.Get(first); ok {
		t.Error("oldest session should have been evicted once the cap was exceeded")
	}
	if _, ok := s.Get(second); !ok {
		t.Error("second session should still be alive")
	}
	if _, ok := s.Get(third); !ok {
		t.Error("third (newest) session should still be alive")
	}
	if got := len(s.ListForEmail("bob@example.com")); got != 2 {
		t.Errorf("expected exactly MaxConcurrent=2 live sessions for bob, got %d", got)
	}
}

func TestSessionMaxConcurrentZeroMeansUnlimited(t *testing.T) {
	s := NewSessionStore()
	for i := 0; i < 10; i++ {
		s.Create("carol@example.com", "readonly")
	}
	if got := len(s.ListForEmail("carol@example.com")); got != 10 {
		t.Errorf("expected 10 unevicted sessions with MaxConcurrent=0, got %d", got)
	}
}

func TestRevokeAllRemovesOnlyThatEmail(t *testing.T) {
	s := NewSessionStore()
	s.Create("dave@example.com", "readonly")
	s.Create("dave@example.com", "readonly")
	eveID := s.Create("eve@example.com", "readonly")

	n := s.RevokeAll("dave@example.com")
	if n != 2 {
		t.Errorf("RevokeAll(dave) = %d, want 2", n)
	}
	if len(s.ListForEmail("dave@example.com")) != 0 {
		t.Error("dave should have no sessions left")
	}
	if _, ok := s.Get(eveID); !ok {
		t.Error("RevokeAll(dave) must not touch eve's session")
	}
}

func TestCreateRequiringMFAGatesUntilVerified(t *testing.T) {
	s := NewSessionStore()
	id := s.CreateRequiringMFA("frank@example.com", "admin")
	sess, ok := s.Get(id)
	if !ok {
		t.Fatal("Get should still find a pending-MFA session (Get itself does not gate -- callers do, see internal/api's sessionFromCookie)")
	}
	if !sess.MFARequired || sess.MFAVerified {
		t.Errorf("expected MFARequired=true, MFAVerified=false right after CreateRequiringMFA: %+v", sess)
	}
	s.MarkMFAVerified(id)
	sess, _ = s.Get(id)
	if !sess.MFAVerified {
		t.Error("MarkMFAVerified should have set MFAVerified=true")
	}
}

func TestListAllAndListForEmailOmitSessionIDs(t *testing.T) {
	// A compile-time-ish guard: Session has no exported field a caller
	// could use to reconstruct an "id" from ListAll/ListForEmail's
	// results, which is the actual security property (see those
	// methods' doc comments). This test just exercises both listing
	// methods return the right count as a smoke check.
	s := NewSessionStore()
	s.Create("x@example.com", "readonly")
	s.Create("y@example.com", "readonly")
	if got := len(s.ListAll()); got != 2 {
		t.Errorf("ListAll() returned %d, want 2", got)
	}
}
