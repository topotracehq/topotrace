/*******************************************************************************
 * @file         directory_test.go
 * @brief        Tests for internal/directory's persisted user records --
 *               upsert/JIT semantics and the deprovisioning check every
 *               login path relies on.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package directory

import (
	"context"
	"testing"

	"topotrace/internal/store/memstore"
)

func TestAllowedNoRecordMeansPermissive(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()
	allowed, err := Allowed(ctx, st, "nobody@example.com")
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	if !allowed {
		t.Error("an email with no directory record at all should be allowed (backward compatible)")
	}
}

func TestProvisionJITCreatesThenRefreshesRole(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()

	u, err := ProvisionJIT(ctx, st, "alice@example.com", "readonly")
	if err != nil {
		t.Fatalf("ProvisionJIT (create): %v", err)
	}
	if u.Source != "jit" || !u.Active || u.Role != "readonly" {
		t.Errorf("unexpected new record: %+v", u)
	}

	u2, err := ProvisionJIT(ctx, st, "alice@example.com", "admin")
	if err != nil {
		t.Fatalf("ProvisionJIT (refresh): %v", err)
	}
	if u2.Role != "admin" {
		t.Errorf("expected role refreshed to admin, got %q", u2.Role)
	}
	if u2.Source != "jit" || u2.CreatedAt != u.CreatedAt {
		t.Errorf("refresh should preserve Source/CreatedAt: got %+v, original %+v", u2, u)
	}
}

func TestDeactivateBlocksSubsequentLogin(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()

	if _, err := ProvisionJIT(ctx, st, "bob@example.com", "readonly"); err != nil {
		t.Fatalf("ProvisionJIT: %v", err)
	}
	if _, err := Deactivate(ctx, st, "bob@example.com"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	allowed, err := Allowed(ctx, st, "bob@example.com")
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	if allowed {
		t.Error("a deactivated user must not be Allowed, even if their IdP still authenticates them")
	}

	// A subsequent JIT provision (the user's IdP still lets them
	// through) must not silently reactivate them.
	u, err := ProvisionJIT(ctx, st, "bob@example.com", "admin")
	if err != nil {
		t.Fatalf("ProvisionJIT after deactivate: %v", err)
	}
	if u.Active {
		t.Error("ProvisionJIT must not reactivate an explicitly deactivated user")
	}
	if u.Role != "admin" {
		t.Errorf("role should still refresh even while deactivated, got %q", u.Role)
	}
}

func TestDeactivateUnknownUserCreatesRecord(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()

	if _, err := Deactivate(ctx, st, "neverloggedin@example.com"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	allowed, err := Allowed(ctx, st, "neverloggedin@example.com")
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	if allowed {
		t.Error("Deactivate must leave an enforceable record even for a never-seen email (SCIM pre-provisioning a deactivation)")
	}
}

func TestListReturnsEveryRecord(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()
	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if _, err := ProvisionJIT(ctx, st, email, "readonly"); err != nil {
			t.Fatalf("ProvisionJIT(%s): %v", email, err)
		}
	}
	users, err := List(ctx, st)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 3 {
		t.Errorf("List() returned %d users, want 3", len(users))
	}
}
