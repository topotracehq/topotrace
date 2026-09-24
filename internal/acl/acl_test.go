/*******************************************************************************
 * @file         acl_test.go
 * @brief        Tests for internal/acl -- policy CRUD and the
 *               visibility/masking Evaluate logic itself.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package acl

import (
	"context"
	"testing"

	"topotrace/internal/model"
	"topotrace/internal/store/memstore"
)

func TestCreateRequiresNameAndSubjects(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()
	if _, err := Create(ctx, st, Policy{Subjects: []string{"readonly"}}); err == nil {
		t.Error("expected error for missing name")
	}
	if _, err := Create(ctx, st, Policy{Name: "x"}); err == nil {
		t.Error("expected error for missing subjects")
	}
	if _, err := Create(ctx, st, Policy{Name: "x", Subjects: []string{"readonly"}, MaskFields: []string{"ssn"}}); err == nil {
		t.Error("expected error for a non-maskable field")
	}
}

func TestCreateListDelete(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()
	p, err := Create(ctx, st, Policy{Name: "hide-db", Subjects: []string{"readonly"}, DenyTags: []string{"db-tier"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.ID == "" {
		t.Error("expected a generated ID")
	}
	list, err := List(ctx, st)
	if err != nil || len(list) != 1 {
		t.Fatalf("List: got %v, %v", list, err)
	}
	if err := Delete(ctx, st, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	list, _ = List(ctx, st)
	if len(list) != 0 {
		t.Errorf("expected empty list after delete, got %d", len(list))
	}
}

func TestEvaluateNoPoliciesFullyVisible(t *testing.T) {
	host := model.Host{Name: "web1", Tags: []string{"prod"}}
	d := Evaluate(nil, "readonly", "someone@example.com", host)
	if !d.Visible || len(d.Masked) != 0 {
		t.Errorf("expected full visibility with no policies, got %+v", d)
	}
}

func TestEvaluateDenyTagsHidesHost(t *testing.T) {
	policies := []Policy{{Name: "no-db", Subjects: []string{"readonly"}, DenyTags: []string{"db-tier"}}}
	dbHost := model.Host{Name: "db1", Tags: []string{"prod", "db-tier"}}
	webHost := model.Host{Name: "web1", Tags: []string{"prod"}}

	if d := Evaluate(policies, "readonly", "x@example.com", dbHost); d.Visible {
		t.Error("db-tier host should be hidden from readonly by DenyTags")
	}
	if d := Evaluate(policies, "readonly", "x@example.com", webHost); !d.Visible {
		t.Error("non-db-tier host should stay visible")
	}
	if d := Evaluate(policies, "admin", "x@example.com", dbHost); !d.Visible {
		t.Error("a policy scoped to \"readonly\" must not apply to a different role")
	}
}

func TestEvaluateAllowTagsRestrictsToMatchingHosts(t *testing.T) {
	policies := []Policy{{Name: "prod-only", Subjects: []string{"*"}, AllowTags: []string{"prod"}}}
	prod := model.Host{Name: "web1", Tags: []string{"prod"}}
	dev := model.Host{Name: "web2", Tags: []string{"dev"}}

	if d := Evaluate(policies, "readonly", "x@example.com", prod); !d.Visible {
		t.Error("prod host should be visible under an AllowTags=prod policy")
	}
	if d := Evaluate(policies, "readonly", "x@example.com", dev); d.Visible {
		t.Error("dev host should be hidden -- it does not carry any AllowTags tag")
	}
}

func TestEvaluateDenyWinsOverAllow(t *testing.T) {
	policies := []Policy{{Name: "conflict", Subjects: []string{"*"}, AllowTags: []string{"prod"}, DenyTags: []string{"prod"}}}
	host := model.Host{Name: "web1", Tags: []string{"prod"}}
	if d := Evaluate(policies, "readonly", "x@example.com", host); d.Visible {
		t.Error("when a policy both allows and denies the same tag, deny must win")
	}
}

func TestEvaluateMasksFields(t *testing.T) {
	policies := []Policy{{Name: "mask-hostname", Subjects: []string{"readonly"}, MaskFields: []string{"hostname"}}}
	host := model.Host{Name: "web1", Tags: []string{"prod"}}
	d := Evaluate(policies, "readonly", "x@example.com", host)
	if !d.Visible {
		t.Fatal("host should remain visible, just masked")
	}
	if !d.MaskedSet()["hostname"] {
		t.Errorf("expected hostname masked, got %v", d.Masked)
	}
	masked := MaskHost(host, d.MaskedSet())
	if masked.Name != RedactedMarker {
		t.Errorf("MaskHost did not redact Name: got %q", masked.Name)
	}
	if len(masked.Tags) != 1 || masked.Tags[0] != "prod" {
		t.Errorf("MaskHost must not touch unrelated fields like Tags: got %v", masked.Tags)
	}
}

func TestEvaluateSubjectMatchesEmailExactly(t *testing.T) {
	policies := []Policy{{Name: "just-bob", Subjects: []string{"bob@example.com"}, DenyTags: []string{"secret"}}}
	host := model.Host{Name: "s1", Tags: []string{"secret"}}
	if d := Evaluate(policies, "readonly", "bob@example.com", host); d.Visible {
		t.Error("policy scoped to bob's exact email should apply to bob")
	}
	if d := Evaluate(policies, "readonly", "alice@example.com", host); !d.Visible {
		t.Error("policy scoped to bob's exact email should not apply to alice")
	}
}
