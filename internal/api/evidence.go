/*******************************************************************************
 * @file         evidence.go
 * @brief        Part of the TopoTrace api module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"time"

	"topotrace/internal/model"
	"topotrace/internal/policy"
)

type askSource struct {
	ID          string     `json:"id"`
	Host        string     `json:"host"`
	Category    string     `json:"category"`
	CollectedAt *time.Time `json:"collected_at,omitempty"`
	State       string     `json:"state"`
	Detail      string     `json:"detail"`
	URL         string     `json:"url"`
}

func appendAskSources(sources []askSource, host model.Host, facts map[string]model.Fact, coverage policy.Coverage, now time.Time) []askSource {
	categories := make([]string, 0, len(facts))
	for category := range facts {
		// Only categories supporting the existing AI summary, never arbitrary
		// user, network or future fact categories.
		switch category {
		case "system_summary", "installed_software", "firewall_av_status", "patch_update_status", "scanner_findings":
			categories = append(categories, category)
		}
	}
	sort.Strings(categories)
	for _, category := range categories {
		f := facts[category]
		data, _ := json.Marshal(f.Data)
		state := "verified"
		if f.CookedAt.IsZero() || f.CookedAt.After(now.Add(5*time.Minute)) {
			state = "unknown"
		} else if policy.IsStale(f.CookedAt, now) {
			state = "outdated"
		}
		for _, e := range coverage.Evidence {
			if e.Category == category {
				state = e.State
			}
		}
		var at *time.Time
		if !f.CookedAt.IsZero() {
			t := f.CookedAt
			at = &t
		}
		sources = append(sources, askSource{ID: fmt.Sprintf("E%d", len(sources)+1), Host: host.Name, Category: category, CollectedAt: at, State: state, Detail: truncateForAudit(string(data), 2000), URL: "#/host/" + url.PathEscape(host.Name)})
	}
	for _, e := range coverage.Evidence {
		if _, ok := facts[e.Category]; !ok {
			sources = append(sources, askSource{ID: fmt.Sprintf("E%d", len(sources)+1), Host: host.Name, Category: e.Category, State: "unknown", Detail: e.Detail, URL: "#/host/" + url.PathEscape(host.Name)})
		}
	}
	return sources
}

var evidenceCitation = regexp.MustCompile(`\[(E[0-9]+)\]`)

// Only IDs actually supplied to the model become links. An ID match is not a
// proof that the source supports the claim; the user can inspect that evidence.
func citedSources(answer string, supplied []askSource) ([]askSource, []string) {
	byID := map[string]askSource{}
	for _, s := range supplied {
		byID[s.ID] = s
	}
	out := []askSource{}
	warnings := []string{}
	seen := map[string]bool{}
	for _, m := range evidenceCitation.FindAllStringSubmatch(answer, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		if s, ok := byID[m[1]]; ok {
			out = append(out, s)
		} else {
			warnings = append(warnings, "The answer cited unavailable evidence "+m[1])
		}
	}
	if len(out) == 0 {
		warnings = append(warnings, "The answer did not cite supplied evidence; verify its claims against host facts.")
	}
	return out, warnings
}
