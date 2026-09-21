/*******************************************************************************
 * @file         draft.go
 * @brief        Part of the TopoTrace aiquery module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package aiquery

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PolicyDraft is a proposed model.Rule, in the same field vocabulary
// POST /api/policies accepts, plus an explanation and a note on how it
// was produced. It is a draft: the operator reviews and creates it (or
// doesn't) -- the AI never writes a rule into the store by itself.
type PolicyDraft struct {
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Threshold        int    `json:"threshold,omitempty"`
	Category         string `json:"category,omitempty"`
	Group            string `json:"group,omitempty"`
	AutoRemediate    string `json:"auto_remediate,omitempty"`
	AutoRemediateArg string `json:"auto_remediate_arg,omitempty"`
	RequireApproval  bool   `json:"require_approval"`
	Explanation      string `json:"explanation"`
	Source           string `json:"source"` // "ask-muster" or "heuristic"
}

// ValidKinds and ValidVerbs are the fixed vocabularies a draft must fit.
var ValidKinds = []string{"stale", "score_below", "category_missing", "vulnerabilities_found"}
var ValidVerbs = []string{"", "restart-service", "apply-updates"}

const draftSystemPrompt = `You turn an operator's plain-English request into exactly one Muster policy rule, as JSON and nothing else.

A rule has these fields:
- "name": short human name (required)
- "kind": one of "stale" (host hasn't reported in 24h), "score_below" (posture score below "threshold"), "category_missing" (fact "category" never reported), "vulnerabilities_found" (any known-vulnerable package)
- "threshold": integer 0-100, only for score_below
- "category": fact category name, only for category_missing (e.g. firewall_av_status, installed_software, tls_certificates, browser_extensions)
- "group": board group to scope to, or "" for every host
- "auto_remediate": "" (none), "restart-service" (needs "auto_remediate_arg" = service name) or "apply-updates"
- "require_approval": true if the operator wants a human to approve the remediation before it runs, or if the request sounds cautious
- "explanation": one sentence on why you chose these fields

If the request can't be expressed with these kinds, pick the closest and say so in "explanation". Reply with only the JSON object.`

// DraftPolicy asks the model for a rule matching description. If Ask
// Muster isn't configured it falls back to heuristicDraft so the
// feature still works (and says so in Source).
func DraftPolicy(ctx context.Context, cfg Config, description string) (PolicyDraft, error) {
	description = strings.TrimSpace(description)
	if description == "" {
		return PolicyDraft{}, fmt.Errorf("aiquery: description is required")
	}
	if !cfg.Enabled() {
		return heuristicDraft(description), nil
	}
	raw, err := Complete(ctx, cfg, draftSystemPrompt, description, 512)
	if err != nil {
		return PolicyDraft{}, err
	}
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(raw, "```json"), "```"), "```")
	var d PolicyDraft
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &d); err != nil {
		return PolicyDraft{}, fmt.Errorf("aiquery: model did not return a rule as JSON: %w", err)
	}
	d.Source = "ask-muster"
	return d, Validate(d)
}

// Validate checks a draft against the fixed vocabularies.
func Validate(d PolicyDraft) error {
	if d.Name == "" {
		return fmt.Errorf("draft has no name")
	}
	if !contains(ValidKinds, d.Kind) {
		return fmt.Errorf("draft kind %q is not one of %s", d.Kind, strings.Join(ValidKinds, ", "))
	}
	if !contains(ValidVerbs, d.AutoRemediate) {
		return fmt.Errorf("draft auto_remediate %q is not one of restart-service, apply-updates", d.AutoRemediate)
	}
	if d.AutoRemediate == "restart-service" && d.AutoRemediateArg == "" {
		return fmt.Errorf("restart-service needs a service name")
	}
	if d.Kind == "score_below" && (d.Threshold <= 0 || d.Threshold > 100) {
		return fmt.Errorf("score_below needs a threshold between 1 and 100")
	}
	if d.Kind == "category_missing" && d.Category == "" {
		return fmt.Errorf("category_missing needs a category")
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

var (
	reThreshold = regexp.MustCompile(`(?i)(?:below|under|less than|<)\s*(\d{1,3})`)
	reGroup     = regexp.MustCompile(`(?i)\b(?:group|column)\s+"?([a-z0-9_-]+)"?`)
	reGroup2    = regexp.MustCompile(`(?i)\b([a-z0-9_-]+)\s+(?:hosts?|servers?|machines?|boxes|fleet)\b`)
	reService   = regexp.MustCompile(`(?i)restart(?:ing)?\s+(?:the\s+)?"?([a-z0-9@._-]+)"?`)
	reCategory  = regexp.MustCompile(`(?i)\b(system_summary|installed_software|disk_usage|running_services|listening_ports|local_users|network_interfaces|scheduled_tasks|patch_update_status|firewall_av_status|browser_extensions|tls_certificates)\b`)
)

// heuristicDraft is the no-API-key fallback: keyword rules over the
// description. Deliberately simple and labeled as such in Source.
func heuristicDraft(desc string) PolicyDraft {
	l := strings.ToLower(desc)
	d := PolicyDraft{Source: "heuristic", Name: titleize(desc)}
	switch {
	case strings.Contains(l, "vulnerab") || strings.Contains(l, "cve"):
		d.Kind = "vulnerabilities_found"
		d.Explanation = "mentions vulnerabilities, so the rule fires on any known-vulnerable package"
	case strings.Contains(l, "stale") || strings.Contains(l, "hasn't reported") || strings.Contains(l, "not reported") || strings.Contains(l, "stopped reporting") || strings.Contains(l, "24h") || strings.Contains(l, "24 hours"):
		d.Kind = "stale"
		d.Explanation = "mentions hosts not reporting, so the rule fires when a host is stale"
	case reCategory.MatchString(l) && (strings.Contains(l, "missing") || strings.Contains(l, "never") || strings.Contains(l, "without") || strings.Contains(l, "no ")):
		d.Kind = "category_missing"
		d.Category = strings.ToLower(reCategory.FindString(l))
		d.Explanation = "mentions a fact category being absent, so the rule fires when it was never reported"
	case reThreshold.MatchString(l) || strings.Contains(l, "score") || strings.Contains(l, "posture"):
		d.Kind = "score_below"
		d.Threshold = 70
		if m := reThreshold.FindStringSubmatch(l); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n <= 100 {
				d.Threshold = n
			}
		}
		d.Explanation = fmt.Sprintf("mentions a score, so the rule fires below %d (say \"below N\" to change it)", d.Threshold)
	default:
		d.Kind = "score_below"
		d.Threshold = 70
		d.Explanation = "couldn't match a specific condition, so this defaults to posture score below 70 -- edit the kind before creating"
	}
	stop := []string{"all", "every", "any", "the", "a", "each", "those", "these", "our", "your", "my", "stale", "new", "old", "which", "on", "of", "for", "in", "when", "flag", "alert", "linux", "windows", "mac", "macos", "prod-like", "managed"}
	if m := reGroup.FindStringSubmatch(desc); m != nil && !contains(stop, strings.ToLower(m[1])) {
		d.Group = strings.ToLower(m[1])
	} else if m := reGroup2.FindStringSubmatch(desc); m != nil && !contains(stop, strings.ToLower(m[1])) {
		d.Group = strings.ToLower(m[1])
	}
	if m := reService.FindStringSubmatch(desc); m != nil {
		d.AutoRemediate, d.AutoRemediateArg = "restart-service", m[1]
	} else if strings.Contains(l, "apply update") || strings.Contains(l, "patch") || strings.Contains(l, "install update") {
		d.AutoRemediate = "apply-updates"
	}
	if d.AutoRemediate != "" && (strings.Contains(l, "approv") || strings.Contains(l, "ask me") || strings.Contains(l, "confirm") || strings.Contains(l, "review")) {
		d.RequireApproval = true
	}
	return d
}

func titleize(desc string) string {
	words := strings.Fields(desc)
	if len(words) > 8 {
		words = words[:8]
	}
	s := strings.Join(words, " ")
	s = strings.TrimRight(s, ".,;:")
	if len(s) > 0 {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}
