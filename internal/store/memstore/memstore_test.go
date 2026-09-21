/*******************************************************************************
 * @file         memstore_test.go
 * @brief        Tests for the Muster memstore package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package memstore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"muster/internal/model"
	"muster/internal/store"
)

func TestQueryReturnsEmptySliceNotNil(t *testing.T) {
	// Regression test: Query and ListFacts used to return a nil slice
	// when nothing matched. Go's json.Marshal encodes a nil slice as
	// `null`, not `[]` -- which broke the web UI's `matches.map(...)`
	// on an empty search result. Both must always return a non-nil,
	// possibly-empty slice.
	ctx := context.Background()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	facts, err := s.Query(ctx, "system_summary", "distribution", "nonexistent")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if facts == nil {
		t.Fatal("Query returned nil slice, want non-nil empty slice")
	}
	if len(facts) != 0 {
		t.Fatalf("Query returned %d results, want 0", len(facts))
	}

	list, err := s.ListFacts(ctx, "no-such-host")
	if err != nil {
		t.Fatalf("ListFacts: %v", err)
	}
	if list == nil {
		t.Fatal("ListFacts returned nil slice, want non-nil empty slice")
	}
}

func TestUpsertFactTracksChanges(t *testing.T) {
	ctx := context.Background()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	// First report: no prior data, so no changes expected.
	changes, err := s.UpsertFact(ctx, model.Fact{
		Host: "h1", Category: "system_summary",
		Data: map[string]any{"distribution": "Ubuntu", "num_cpus": 2},
	})
	if err != nil {
		t.Fatalf("UpsertFact (initial): %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected no changes on first report, got %v", changes)
	}

	// Second report: one field changed, one added.
	changes, err = s.UpsertFact(ctx, model.Fact{
		Host: "h1", Category: "system_summary",
		Data: map[string]any{"distribution": "Fedora", "num_cpus": 2, "memory_mb": 4096},
	})
	if err != nil {
		t.Fatalf("UpsertFact (update): %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d: %v", len(changes), changes)
	}

	fact, ok, err := s.GetFact(ctx, "h1", "system_summary")
	if err != nil || !ok {
		t.Fatalf("GetFact: ok=%v err=%v", ok, err)
	}
	if fact.Data["distribution"] != "Fedora" {
		t.Fatalf("stored fact not updated: %v", fact.Data)
	}
}

func TestQueryMatchesSubstring(t *testing.T) {
	ctx := context.Background()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"})
	_, _ = s.UpsertFact(ctx, model.Fact{
		Host: "h1", Category: "system_summary",
		Data: map[string]any{"distribution": "Ubuntu 22.04"},
	})

	matches, err := s.Query(ctx, "system_summary", "distribution", "ubuntu")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 case-insensitive match, got %d", len(matches))
	}
}

func TestSetHostGroupAndTags(t *testing.T) {
	ctx := context.Background()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := s.SetHostGroup(ctx, "no-such-host", "prod"); !errors.Is(err, store.ErrHostNotFound) {
		t.Fatalf("SetHostGroup on unknown host: got %v, want ErrHostNotFound", err)
	}

	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	h, err := s.SetHostGroup(ctx, "h1", "prod")
	if err != nil {
		t.Fatalf("SetHostGroup: %v", err)
	}
	if h.Group != "prod" {
		t.Fatalf("SetHostGroup didn't stick: %+v", h)
	}

	h, err = s.SetHostTags(ctx, "h1", []string{"needs-patching", "east-dc"})
	if err != nil {
		t.Fatalf("SetHostTags: %v", err)
	}
	if len(h.Tags) != 2 || h.Tags[0] != "needs-patching" {
		t.Fatalf("SetHostTags didn't stick: %+v", h)
	}

	// A re-cook (UpsertHost, as the pipeline calls it, with no Group/Tags
	// set) must not clobber the group/tags an operator assigned.
	if err := s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"}); err != nil {
		t.Fatalf("UpsertHost (re-cook): %v", err)
	}
	h, _, err = s.GetHost(ctx, "h1")
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.Group != "prod" || len(h.Tags) != 2 {
		t.Fatalf("re-cook clobbered group/tags: %+v", h)
	}
}

func TestListChanges(t *testing.T) {
	ctx := context.Background()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.UpsertHost(ctx, model.Host{Name: "h1", Platform: "linux"})
	_ = s.UpsertHost(ctx, model.Host{Name: "h2", Platform: "linux"})

	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h1", Category: "system_summary", Data: map[string]any{"distribution": "Ubuntu"}}); err != nil {
		t.Fatalf("UpsertFact h1 (initial): %v", err)
	}
	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h1", Category: "system_summary", Data: map[string]any{"distribution": "Fedora"}}); err != nil {
		t.Fatalf("UpsertFact h1 (update): %v", err)
	}
	if _, err := s.UpsertFact(ctx, model.Fact{Host: "h2", Category: "system_summary", Data: map[string]any{"distribution": "Ubuntu"}}); err != nil {
		t.Fatalf("UpsertFact h2 (initial): %v", err)
	}

	changes, err := s.ListChanges(ctx, "h1", 0)
	if err != nil {
		t.Fatalf("ListChanges: %v", err)
	}
	if len(changes) != 1 || changes[0].Field != "distribution" {
		t.Fatalf("expected 1 change for h1, got %v", changes)
	}

	none, err := s.ListChanges(ctx, "no-such-host", 0)
	if err != nil {
		t.Fatalf("ListChanges: %v", err)
	}
	if none == nil || len(none) != 0 {
		t.Fatalf("expected non-nil empty slice for unknown host, got %v", none)
	}
}

func TestDocumentsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetDocument(ctx, "k", "a"); ok {
		t.Fatal("expected no document yet")
	}
	if err := s.PutDocument(ctx, model.Document{Kind: "k", ID: "b", Data: json.RawMessage(`{"n":2}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDocument(ctx, model.Document{Kind: "k", ID: "a", Data: json.RawMessage(`{"n":1}`)}); err != nil {
		t.Fatal(err)
	}
	d, ok, err := s.GetDocument(ctx, "k", "a")
	if err != nil || !ok || string(d.Data) != `{"n":1}` || d.UpdatedAt.IsZero() {
		t.Fatalf("GetDocument: ok=%v err=%v doc=%+v", ok, err, d)
	}
	list, err := s.ListDocuments(ctx, "k")
	if err != nil || len(list) != 2 || list[0].ID != "a" || list[1].ID != "b" {
		t.Fatalf("ListDocuments: %+v err=%v", list, err)
	}
	if err := s.PutDocument(ctx, model.Document{Kind: "k", ID: "a", Data: json.RawMessage(`{"n":3}`)}); err != nil {
		t.Fatal(err)
	}
	d, _, _ = s.GetDocument(ctx, "k", "a")
	if string(d.Data) != `{"n":3}` {
		t.Fatalf("expected replace, got %s", d.Data)
	}
	if err := s.DeleteDocument(ctx, "k", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDocument(ctx, "k", "a"); !errors.Is(err, store.ErrDocumentNotFound) {
		t.Fatalf("expected ErrDocumentNotFound, got %v", err)
	}
	if list, _ := s.ListDocuments(ctx, "other"); len(list) != 0 {
		t.Fatal("expected empty list for unknown kind")
	}
}
