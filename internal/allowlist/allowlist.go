/*******************************************************************************
 * @file         allowlist.go
 * @brief        Package allowlist cross-references a host's installed_software fact against operator-defined SoftwareRules -- deny rules (banned software) and allow rules (an explicit allowlist, once one exists for a scope).
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package allowlist cross-references a host's installed_software fact
// against operator-defined SoftwareRules -- deny rules (banned
// software) and allow rules (an explicit allowlist, once one exists for
// a scope). Deliberately small and honest, the same spirit as
// internal/vuln's static dataset and internal/policy's posture score:
// exact-or-prefix name matching, no version ranges, no package-manager
// metadata beyond name/version -- see model.SoftwareRule's doc comment
// for the exact semantics.
package allowlist

import (
	"strings"

	"topotrace/internal/model"
)

// Violation is one installed package that fails a rule in scope.
type Violation struct {
	Rule    string `json:"rule"`
	Kind    string `json:"kind"` // "deny" or "allow"
	Package string `json:"package"`
	Version string `json:"version"`
}

// Evaluate returns every violation of rules (already filtered to this
// host's scope by the caller, the same group-filtering convention
// internal/evaluator applies to model.Rule) against itemsRaw (an
// installed_software fact's Data["items"], as internal/cook produces
// it -- a list of {"name":..., "version":...} maps).
//
// Deny rules always apply. Allow rules only start enforcing once at
// least one exists in rules -- with none, Evaluate never reports an
// "unauthorized software" violation, since there's no allowlist to be
// unauthorized against yet.
func Evaluate(itemsRaw any, rules []model.SoftwareRule) []Violation {
	items := asItems(itemsRaw)
	if len(items) == 0 || len(rules) == 0 {
		return nil
	}

	var denyRules, allowRules []model.SoftwareRule
	for _, r := range rules {
		switch r.Kind {
		case "deny":
			denyRules = append(denyRules, r)
		case "allow":
			allowRules = append(allowRules, r)
		}
	}

	var violations []Violation
	for _, item := range items {
		name, _ := item["name"].(string)
		version, _ := item["version"].(string)
		if name == "" {
			continue
		}

		for _, r := range denyRules {
			if matches(r.Match, name) {
				violations = append(violations, Violation{Rule: r.Name, Kind: "deny", Package: name, Version: version})
				break // one deny hit per package is enough to report
			}
		}

		if len(allowRules) == 0 {
			continue // no allowlist configured for this scope -- "unknown," not "unauthorized"
		}
		allowed := false
		for _, r := range allowRules {
			if matches(r.Match, name) {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, Violation{Rule: "(not on allowlist)", Kind: "allow", Package: name, Version: version})
		}
	}
	return violations
}

// matches reports whether name satisfies pattern -- case-insensitive
// exact match, or a prefix match when pattern ends with "*".
func matches(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	name = strings.ToLower(strings.TrimSpace(name))
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// ShadowAIPattern is one built-in, pre-seeded signature for a known AI
// desktop app, CLI tool, or browser extension "package" -- the same
// "small, curated, static list, not a live feed" spirit as
// internal/vuln.Dataset. Name is documentation only (shown in the
// violation as which tool matched); Match follows the same
// case-insensitive exact-or-trailing-"*"-wildcard semantics as
// model.SoftwareRule.Match.
type ShadowAIPattern struct {
	Name  string
	Match string
}

// ShadowAIPatterns is TopoTrace's built-in "shadow AI" detection ruleset:
// AI desktop apps, CLI tools, and browser-extension packages that
// commonly show up in an installed_software fact without ever having
// been approved by anyone -- the same "invisible SaaS/tool sprawl"
// problem enterprise browser security products (Island among them)
// build shadow-IT/shadow-AI detection around. Unlike model.SoftwareRule,
// this list ships with the binary and needs no operator setup -- every
// TopoTrace deployment can answer "do we have unauthorized AI tooling
// installed anywhere" on day one.
var ShadowAIPatterns = []ShadowAIPattern{
	{"ChatGPT desktop", "chatgpt*"},
	{"OpenAI tooling", "openai*"},
	{"Ollama", "ollama*"},
	{"LM Studio", "lm studio*"},
	{"LM Studio", "lmstudio*"},
	{"Claude desktop", "claude*"},
	{"GitHub Copilot", "github copilot*"},
	{"Copilot", "copilot*"},
	{"Google Gemini", "gemini*"},
	{"Google Bard", "bard*"},
	{"Perplexity AI", "perplexity*"},
	{"Poe", "poe*"},
	{"Jasper AI", "jasper*"},
	{"Character.AI", "character.ai*"},
	{"Cursor (AI code editor)", "cursor*"},
	{"Sider AI browser extension", "sider*"},
	{"Monica AI browser extension", "monica*"},
	{"DeepSeek", "deepseek*"},
	{"Simon Willison's llm CLI", "llm-cli*"},
	{"aichat CLI", "aichat*"},
}

// EvaluateShadowAI cross-references itemsRaw (an installed_software
// fact's Data["items"], same shape Evaluate takes) against
// ShadowAIPatterns, returning one Violation (Kind "shadow_ai") per
// installed item that matches a known AI tool signature. allowRules
// narrows that down to what's actually been explicitly sanctioned for
// this host's scope: an AI tool an operator has approved via a Kind
// "allow" model.SoftwareRule (the exact same allow-rule semantics
// Evaluate's deny/allow rules already use) is silently excluded --
// approved software isn't shadow IT. Deliberately independent of
// Evaluate's own allow-rule "enforcement only starts once one exists"
// behavior: an allow rule that exists only to sanction one AI tool
// should not, as a side effect, switch on full allowlist enforcement
// for every other package in that rule's scope, so this function checks
// allowRules purely as an allow-list lookup, never as an
// enable-enforcement signal.
func EvaluateShadowAI(itemsRaw any, allowRules []model.SoftwareRule) []Violation {
	items := asItems(itemsRaw)
	if len(items) == 0 {
		return nil
	}

	var violations []Violation
	for _, item := range items {
		name, _ := item["name"].(string)
		version, _ := item["version"].(string)
		if name == "" {
			continue
		}

		var matched string
		for _, p := range ShadowAIPatterns {
			if matches(p.Match, name) {
				matched = p.Name
				break
			}
		}
		if matched == "" {
			continue
		}

		allowed := false
		for _, r := range allowRules {
			if r.Kind == "allow" && matches(r.Match, name) {
				allowed = true
				break
			}
		}
		if allowed {
			continue
		}

		violations = append(violations, Violation{Rule: matched, Kind: "shadow_ai", Package: name, Version: version})
	}
	return violations
}

// asItems normalizes an installed_software fact's Data["items"] the
// same way internal/vuln.CheckWithFeed does -- []any (memstore, or
// pgstore after a JSONB round trip) or []map[string]any (constructed
// directly, e.g. in tests).
func asItems(itemsRaw any) []map[string]any {
	switch v := itemsRaw.(type) {
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, raw := range v {
			if m, ok := raw.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case []map[string]any:
		return v
	default:
		return nil
	}
}
