/*******************************************************************************
 * @file         governance_test.go
 * @brief        Tests for the TopoTrace governance package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package governance

import (
	"path/filepath"
	"testing"
)

func TestStoreAddRemoveList(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("fresh store not empty: %+v", entries)
	}

	if _, err := s.Apply("add", Entry{Kind: "tool", Value: "claude"}); err != nil {
		t.Fatalf("Apply add: %v", err)
	}
	entries, err = s.Apply("add", Entry{Kind: "mcp_command", Value: "npx"})
	if err != nil {
		t.Fatalf("Apply add: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}

	// Adding a duplicate is a no-op, not a second entry.
	entries, err = s.Apply("add", Entry{Kind: "tool", Value: "claude"})
	if err != nil {
		t.Fatalf("Apply add dup: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("dup add changed count: %+v", entries)
	}

	entries, err = s.Apply("remove", Entry{Kind: "tool", Value: "claude"})
	if err != nil {
		t.Fatalf("Apply remove: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "npx" {
		t.Fatalf("got %+v after remove", entries)
	}

	if _, err := s.Apply("bogus-op", Entry{Kind: "tool", Value: "x"}); err == nil {
		t.Fatal("expected error for unknown op")
	}
	if _, err := s.Apply("add", Entry{Kind: "bogus", Value: "x"}); err == nil {
		t.Fatal("expected error for invalid entry kind")
	}
	if _, err := s.Apply("add", Entry{Kind: "tool", Value: ""}); err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestStorePersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := s1.Apply("add", Entry{Kind: "tool", Value: "cursor"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	s2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("re-NewStore: %v", err)
	}
	entries, err := s2.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "cursor" {
		t.Fatalf("got %+v, want [{tool cursor}]", entries)
	}

	if got := filepath.Join(dir, "policy.json"); got != s2.path {
		t.Fatalf("path = %q, want %q", s2.path, got)
	}
}

func TestViolations(t *testing.T) {
	allowed := []Entry{
		{Kind: "tool", Value: "claude"},
		{Kind: "mcp_command", Value: "npx"},
	}

	findings := []Finding{
		{Kind: "tool", Tool: &struct {
			Name string `json:"name"`
		}{Name: "claude"}},
		{Kind: "tool", Tool: &struct {
			Name string `json:"name"`
		}{Name: "aider"}},
		{Kind: "mcp_server", MCPServer: &struct {
			Command string `json:"command"`
			Name    string `json:"name"`
		}{Command: "npx", Name: "filesystem"}},
		{Kind: "mcp_server", MCPServer: &struct {
			Command string `json:"command"`
			Name    string `json:"name"`
		}{Command: "/opt/weird/binary", Name: "shady"}},
		{Kind: "key_presence"}, // not policy-relevant, must be ignored
	}

	violations := Violations(findings, allowed)
	if len(violations) != 2 {
		t.Fatalf("got %d violations, want 2: %+v", len(violations), violations)
	}
	if violations[0].Finding.Tool.Name != "aider" {
		t.Fatalf("first violation = %+v, want tool aider", violations[0])
	}
	if violations[1].Finding.MCPServer.Command != "/opt/weird/binary" {
		t.Fatalf("second violation = %+v, want the shady MCP server", violations[1])
	}
}

func TestViolationsEmptyAllowlistFlagsEverything(t *testing.T) {
	findings := []Finding{
		{Kind: "tool", Tool: &struct {
			Name string `json:"name"`
		}{Name: "claude"}},
	}
	violations := Violations(findings, nil)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(violations))
	}
}
