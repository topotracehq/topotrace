/*******************************************************************************
 * @file         governance.go
 * @brief        Package governance is the policy/violation logic for the ai-governance plugin, kept free of RPC/HTTP plumbing so it's testable as plain functions.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package governance is the policy/violation logic for the
// ai-governance plugin, kept free of RPC/HTTP plumbing so it's
// testable as plain functions. It layers an approved-tools/
// approved-MCP-commands allowlist on top of the Community visibility
// findings internal/aiagentinv already produces: the visibility layer
// scores and shows everything it finds, this layer says what's
// actually out of policy.
package governance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Entry is one allowlist entry. Kind is "tool" (an AI CLI/agent tool
// name, matched against aiagentinv.Tool.Name) or "mcp_command" (an MCP
// server command, matched against aiagentinv.MCPServer.Command).
type Entry struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (e Entry) valid() bool {
	return (e.Kind == "tool" || e.Kind == "mcp_command") && e.Value != ""
}

// Finding is the subset of internal/aiagentinv.Finding this package
// needs to check against policy -- duplicated here (rather than
// importing muster/internal/aiagentinv) so the plugin binary has no
// compile-time dependency on core internals, only on the JSON shape
// the core's /api/hosts/{host}/ai-agents endpoint already serves.
type Finding struct {
	Kind string `json:"kind"`
	Tool *struct {
		Name string `json:"name"`
	} `json:"tool,omitempty"`
	MCPServer *struct {
		Command string `json:"command"`
		Name    string `json:"name"`
	} `json:"mcp_server,omitempty"`
	Level string `json:"level"`
}

// Violation is one finding that is not covered by the allowlist.
type Violation struct {
	Finding Finding `json:"finding"`
	Reason  string  `json:"reason"`
}

// Store is a JSON-file-backed allowlist. A first slice's storage need:
// no concurrent-writer coordination beyond an in-process mutex, no
// schema migrations, easy to read/edit by hand. If this plugin grows
// real multi-tenant or high-write-volume needs later, swapping in
// SQLite is a contained change -- the Store interface below is small
// on purpose.
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore opens (or creates) the allowlist file at dataDir/policy.json.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	s := &Store{path: filepath.Join(dataDir, "policy.json")}
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		if err := s.save(nil); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) load() ([]Entry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	return entries, nil
}

func (s *Store) save(entries []Entry) error {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Value < entries[j].Value
	})
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// List returns the current allowlist.
func (s *Store) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.load()
	if entries == nil {
		entries = []Entry{}
	}
	return entries, err
}

// Apply adds or removes an entry. op must be "add" or "remove".
func (s *Store) Apply(op string, e Entry) ([]Entry, error) {
	if !e.valid() {
		return nil, fmt.Errorf("invalid entry: kind must be \"tool\" or \"mcp_command\" and value must be non-empty, got %+v", e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.load()
	if err != nil {
		return nil, err
	}
	switch op {
	case "add":
		found := false
		for _, existing := range entries {
			if existing == e {
				found = true
				break
			}
		}
		if !found {
			entries = append(entries, e)
		}
	case "remove":
		out := entries[:0]
		for _, existing := range entries {
			if existing != e {
				out = append(out, existing)
			}
		}
		entries = out
	default:
		return nil, fmt.Errorf("unknown op %q: want \"add\" or \"remove\"", op)
	}
	if err := s.save(entries); err != nil {
		return nil, err
	}
	if entries == nil {
		entries = []Entry{}
	}
	return entries, nil
}

// Violations returns the findings that are NOT covered by allowed.
// Only "tool" and "mcp_server" kinds are policy-relevant here --
// key_presence findings are a different kind of risk (secret hygiene,
// not "is this tool approved") and are left to the visibility layer.
func Violations(findings []Finding, allowed []Entry) []Violation {
	allowedTools := map[string]bool{}
	allowedCommands := map[string]bool{}
	for _, e := range allowed {
		switch e.Kind {
		case "tool":
			allowedTools[e.Value] = true
		case "mcp_command":
			allowedCommands[e.Value] = true
		}
	}

	var out []Violation
	for _, f := range findings {
		switch f.Kind {
		case "tool":
			if f.Tool == nil {
				continue
			}
			if !allowedTools[f.Tool.Name] {
				out = append(out, Violation{Finding: f, Reason: fmt.Sprintf("tool %q is not on the approved-tools allowlist", f.Tool.Name)})
			}
		case "mcp_server":
			if f.MCPServer == nil {
				continue
			}
			if !allowedCommands[f.MCPServer.Command] {
				out = append(out, Violation{Finding: f, Reason: fmt.Sprintf("MCP server %q (command %q) is not on the approved-MCP-commands allowlist", f.MCPServer.Name, f.MCPServer.Command)})
			}
		}
	}
	return out
}
