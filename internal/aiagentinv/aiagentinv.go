/*******************************************************************************
 * @file         aiagentinv.go
 * @brief        Part of the TopoTrace aiagentinv module.
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

import (
	"fmt"
	"sort"
)

// Tool is one AI CLI/IDE-agent tool the agent found installed on a host.
type Tool struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
}

// MCPServer is one MCP server definition the agent found in a config
// file (Claude Desktop/Code, Cursor, Codeium, or a bare mcp.json/
// mcp_servers.json). Env is deliberately absent -- see KeyPresence.
type MCPServer struct {
	Source  string   `json:"source"` // path of the config file it came from
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// KeyPresence is one model-provider API key environment variable name
// found set (non-empty) somewhere -- never the value itself.
type KeyPresence struct {
	Provider   string `json:"provider"` // env var name, e.g. "ANTHROPIC_API_KEY"
	Source     string `json:"source"`   // file it was found in
	WorldGroup bool   `json:"world_group_readable"`
}

// Finding is one evaluated record -- a Tool, MCPServer, or KeyPresence --
// with its risk verdict. Kind disambiguates which of Tool, MCPServer,
// and KeyPresence is populated; the other two are nil.
type Finding struct {
	Kind        string       `json:"kind"` // "tool", "mcp_server", "key_presence"
	Tool        *Tool        `json:"tool,omitempty"`
	MCPServer   *MCPServer   `json:"mcp_server,omitempty"`
	KeyPresence *KeyPresence `json:"key_presence,omitempty"`
	Level       string       `json:"level"` // "high", "medium", "low"
	Reasons     []string     `json:"reasons"`
	Score       int          `json:"score"` // 0-100, higher is riskier
}

// KnownExpected is a small, curated allowlist of MCP server commands
// that are common and legitimate -- an illustrative placeholder, like
// internal/browserext's Trusted map, not a claim about any real
// server's safety. An MCP server whose command isn't recognized here
// isn't inherently bad; it's simply unreviewed, and scores medium as
// "worth a look" rather than a verdict.
var KnownExpected = map[string]string{
	"npx":     "npm package runner -- common for @modelcontextprotocol/* servers",
	"uvx":     "Python package runner -- common for community MCP servers",
	"node":    "direct Node.js invocation",
	"python":  "direct Python invocation",
	"python3": "direct Python invocation",
	"docker":  "containerized MCP server",
}

// KnownTools is a small, curated set of AI CLI/IDE-agent tool names
// this collector looks for -- recognized ones are informational only
// (visibility, not a risk verdict); this list documents what the
// collector was written to expect, not a completeness claim.
var KnownTools = map[string]bool{
	"claude": true, "gh-copilot": true, "cursor": true, "aider": true,
	"codex": true, "continue": true, "cody": true, "windsurf": true, "ollama": true,
}

// FromFact converts an ai_agent_inventory fact's "tools", "mcp_servers",
// and "keys" lists into their typed forms.
func FromFact(fact map[string]any) (tools []Tool, servers []MCPServer, keys []KeyPresence) {
	for _, raw := range anyList(fact["tools"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tools = append(tools, Tool{Name: str(m["name"]), Path: str(m["path"]), Version: str(m["version"])})
	}
	for _, raw := range anyList(fact["mcp_servers"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		servers = append(servers, MCPServer{Source: str(m["source"]), Name: str(m["name"]), Command: str(m["command"]), Args: strs(m["args"])})
	}
	for _, raw := range anyList(fact["keys"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		wg, _ := m["world_group_readable"].(bool)
		keys = append(keys, KeyPresence{Provider: str(m["provider"]), Source: str(m["source"]), WorldGroup: wg})
	}
	return
}

// Evaluate scores every tool, MCP server, and key-presence record.
// Findings come back riskiest first.
func Evaluate(tools []Tool, servers []MCPServer, keys []KeyPresence) []Finding {
	out := make([]Finding, 0, len(tools)+len(servers)+len(keys))

	for _, t := range tools {
		tCopy := t
		f := Finding{Kind: "tool", Tool: &tCopy, Level: "low"}
		if !KnownTools[t.Name] {
			f.Score = 5
			f.Reasons = append(f.Reasons, "AI CLI/agent tool found -- not on the curated known-tools list, informational only")
		} else {
			f.Reasons = append(f.Reasons, "recognized AI CLI/agent tool")
		}
		out = append(out, f)
	}

	for _, s := range servers {
		sCopy := s
		f := Finding{Kind: "mcp_server", MCPServer: &sCopy}
		if reason, ok := KnownExpected[s.Command]; ok {
			f.Score = 5
			f.Level = "low"
			f.Reasons = append(f.Reasons, "command on the known-expected list: "+reason)
		} else {
			f.Score = 30
			f.Level = "medium"
			f.Reasons = append(f.Reasons, fmt.Sprintf("MCP server command %q is not on the curated known-expected list -- worth review", s.Command))
		}
		out = append(out, f)
	}

	for _, k := range keys {
		kCopy := k
		f := Finding{Kind: "key_presence", KeyPresence: &kCopy}
		f.Reasons = append(f.Reasons, fmt.Sprintf("%s is set in %s", k.Provider, k.Source))
		if k.WorldGroup {
			f.Score = 70
			f.Level = "high"
			f.Reasons = append(f.Reasons, "found in a file readable by group or other -- the key name is plaintext-visible to other local accounts")
		} else {
			f.Score = 10
			f.Level = "low"
		}
		out = append(out, f)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// Risky returns only the medium/high findings -- what a compliance
// check or a fleet tile counts.
func Risky(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Level != "low" {
			out = append(out, f)
		}
	}
	return out
}

func anyList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []map[string]any:
		out := make([]any, 0, len(t))
		for _, m := range t {
			out = append(out, m)
		}
		return out
	}
	return nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strs(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
