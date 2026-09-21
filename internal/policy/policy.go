/*******************************************************************************
 * @file         policy.go
 * @brief        Package policy is Muster's start on a rule-evaluation layer over cooked facts -- deliberately small: one real rule (staleness), evaluated server-side so /api and the web UI's board agree on the same answer, instead of the board computing...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package policy is Muster's start on a rule-evaluation layer over
// cooked facts -- deliberately small: one real rule (staleness),
// evaluated server-side so /api and the web UI's board agree on the
// same answer, instead of the board computing it client-side with
// nothing enforcing it anywhere else. A fuller rule layer (arbitrary
// named rules like "flag hosts on an unpatched kernel version",
// persisted and evaluated on a schedule with real alerting) is real,
// separate scope -- this is the foundation it would sit on, not a
// stand-in for it.
package policy

import (
	"fmt"
	"strings"
	"time"

	"muster/internal/model"
)

// StaleAfter is how long a host can go without reporting before it's
// considered stale. Matches the web UI's pre-existing client-side
// STALE_MS heuristic exactly (24h) -- this package is what makes that
// number a real, server-enforced rule instead of only a display
// convenience the browser computes on its own.
const StaleAfter = 24 * time.Hour

// IsStale reports whether a host last cooked at lastCooked should be
// considered stale as of now. A zero lastCooked (never reported) counts
// as stale -- there's no "recent enough" data to say otherwise.
func IsStale(lastCooked, now time.Time) bool {
	if lastCooked.IsZero() {
		return true
	}
	return now.Sub(lastCooked) > StaleAfter
}

// PostureResult is a lightweight, on-demand compliance score for one
// host -- never stored, always reflects whatever facts are passed in.
// This is a heuristic, not a claim of formal/audited compliance: it
// combines a small, fixed set of checks over fact categories this
// project already collects, the same "small and honest, not a
// stand-in for a real audit" spirit as everything else in this package.
type PostureResult struct {
	Score    int      `json:"score"`
	Findings []string `json:"findings"`
	Coverage Coverage `json:"coverage"`
}

// ComputePosture scores a host out of 100, starting clean and
// subtracting only for a concrete issue it can actually observe.
// Deliberately never penalizes a category that's simply absent (an
// agent that doesn't collect firewall status yet, or a platform this
// heuristic has no opinion about, is "unknown," not "bad") -- only a
// category that's present and says something concerning.
func ComputePosture(platform string, facts map[string]model.Fact, stale bool) PostureResult {
	score := 100
	var findings []string

	if stale {
		score -= 40
		findings = append(findings, "host hasn't reported within the staleness threshold")
	}

	if fw, ok := facts["firewall_av_status"]; ok {
		switch platform {
		case "linux":
			if status, _ := fw.Data["ufw_status"].(string); status == "inactive" {
				score -= 20
				findings = append(findings, "ufw firewall is inactive")
			}
		case "windows":
			for k, v := range fw.Data {
				if !strings.HasSuffix(k, "_enabled") {
					continue
				}
				if s, _ := v.(string); s == "False" {
					score -= 20
					findings = append(findings, fmt.Sprintf("Windows firewall profile %q is disabled", strings.TrimSuffix(k, "_enabled")))
					break // one penalty for "at least one profile off," not stacked per profile
				}
			}
		}
	}

	// Pending-update counts are only meaningful on Linux today --
	// patch_update_status on Windows reports installed hotfixes, not a
	// pending count (see cookWinHotfixes's doc comment), so there's
	// nothing comparable to score there yet.
	if pu, ok := facts["patch_update_status"]; ok && platform == "linux" {
		if n, isNum := asNumber(pu.Data["count"]); isNum && n > 0 {
			penalty := int(n) * 2
			if penalty > 20 {
				penalty = 20
			}
			score -= penalty
			findings = append(findings, fmt.Sprintf("%d pending package update(s)", int(n)))
		}
	}

	if score < 0 {
		score = 0
	}
	return PostureResult{Score: score, Findings: findings, Coverage: CollectionCoverage(platform, facts, time.Now().UTC())}
}

// asNumber extracts a float64 from a JSON-decoded value that may be a
// native Go int (memstore, same-process) or a float64 (pgstore, after a
// JSONB round trip through encoding/json) -- model.Fact.Data is
// deliberately opaque JSON, so any code reading a numeric field back out
// of it has to tolerate both representations.
func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
