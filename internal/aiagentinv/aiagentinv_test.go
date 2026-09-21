/*******************************************************************************
 * @file         aiagentinv_test.go
 * @brief        Tests for the TopoTrace aiagentinv package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package aiagentinv

import "testing"

func TestEvaluateLevels(t *testing.T) {
	tools := []Tool{
		{Name: "claude", Path: "/usr/local/bin/claude", Version: "1.2.3"},
		{Name: "sketchy-agent", Path: "/home/dev/.local/bin/sketchy-agent"},
	}
	servers := []MCPServer{
		{Source: "/home/dev/.claude.json", Name: "filesystem", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}},
		{Source: "/home/dev/.cursor/mcp.json", Name: "weird", Command: "/home/dev/mystery.sh"},
	}
	keys := []KeyPresence{
		{Provider: "ANTHROPIC_API_KEY", Source: "/home/dev/.bashrc", WorldGroup: false},
		{Provider: "OPENAI_API_KEY", Source: "/home/dev/.claude.json", WorldGroup: true},
	}

	findings := Evaluate(tools, servers, keys)
	if len(findings) != 6 {
		t.Fatalf("expected 6 findings, got %d", len(findings))
	}
	if findings[0].Kind != "key_presence" || findings[0].Level != "high" {
		t.Fatalf("riskiest should be the world/group-readable key: %+v", findings[0])
	}

	var claudeTool, sketchyTool, npxServer, weirdServer, safeKey, exposedKey Finding
	for _, f := range findings {
		switch {
		case f.Kind == "tool" && f.Tool.Name == "claude":
			claudeTool = f
		case f.Kind == "tool" && f.Tool.Name == "sketchy-agent":
			sketchyTool = f
		case f.Kind == "mcp_server" && f.MCPServer.Command == "npx":
			npxServer = f
		case f.Kind == "mcp_server" && f.MCPServer.Name == "weird":
			weirdServer = f
		case f.Kind == "key_presence" && !f.KeyPresence.WorldGroup:
			safeKey = f
		case f.Kind == "key_presence" && f.KeyPresence.WorldGroup:
			exposedKey = f
		}
	}

	if claudeTool.Level != "low" || len(claudeTool.Reasons) != 1 {
		t.Fatalf("known tool should be low, single reason: %+v", claudeTool)
	}
	if sketchyTool.Level != "low" {
		t.Fatalf("unrecognized tool is still low (informational): %+v", sketchyTool)
	}
	if npxServer.Level != "low" {
		t.Fatalf("known-expected MCP command should be low: %+v", npxServer)
	}
	if weirdServer.Level != "medium" {
		t.Fatalf("unrecognized MCP command should be medium: %+v", weirdServer)
	}
	if safeKey.Level != "low" {
		t.Fatalf("key in a private file should be low: %+v", safeKey)
	}
	if exposedKey.Level != "high" || len(exposedKey.Reasons) != 2 {
		t.Fatalf("world/group-readable key should be high with 2 reasons: %+v", exposedKey)
	}

	risky := Risky(findings)
	if len(risky) != 2 { // exposedKey (high) + weirdServer (medium)
		t.Fatalf("expected 2 risky findings, got %d: %+v", len(risky), risky)
	}
}

func TestFromFact(t *testing.T) {
	fact := map[string]any{
		"tools": []any{
			map[string]any{"name": "claude", "path": "/usr/local/bin/claude", "version": "1.0"},
		},
		"mcp_servers": []any{
			map[string]any{"source": "/home/dev/.claude.json", "name": "fs", "command": "npx", "args": []any{"-y", "pkg"}},
		},
		"keys": []any{
			map[string]any{"provider": "ANTHROPIC_API_KEY", "source": "/home/dev/.bashrc", "world_group_readable": true},
		},
	}
	tools, servers, keys := FromFact(fact)
	if len(tools) != 1 || tools[0].Name != "claude" {
		t.Fatalf("tools: %+v", tools)
	}
	if len(servers) != 1 || servers[0].Command != "npx" || len(servers[0].Args) != 2 {
		t.Fatalf("servers: %+v", servers)
	}
	if len(keys) != 1 || !keys[0].WorldGroup {
		t.Fatalf("keys: %+v", keys)
	}
}
