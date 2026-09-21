/*******************************************************************************
 * @file         risk.go
 * @brief        Package risk blends the separate signals Muster already computes for a host -- vulnerability findings and their severity, posture score, staleness, Shadow AI and software-policy violations -- with two operator-supplied facts about the ho...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package risk blends the separate signals Muster already computes for a
// host -- vulnerability findings and their severity, posture score,
// staleness, Shadow AI and software-policy violations -- with two
// operator-supplied facts about the host (how critical it is, and
// whether it's exposed to the internet) into one 0-100 risk score,
// higher meaning riskier. This is the "one number that matters" that
// vulnerability-management tooling leans on: a critical CVE on an
// internet-facing database server is not the same problem as the same
// CVE on an internal build box, and a per-host risk score is how that
// difference gets ranked instead of argued about.
//
// The weights are illustrative and documented in the Factor breakdown
// every Result carries, so a reader can see exactly why a host scored
// what it did. Criticality and exposure come from host tags (see
// CriticalityOf/ExposureOf) rather than new schema, so they're set from
// the existing tag editor on the host page.
package risk

import (
	"fmt"
	"sort"
	"strings"

	"muster/internal/browserext"
	"muster/internal/certs"
	"muster/internal/compliance"
)

// Factor is one contribution to a Result's score, for explainability.
type Factor struct {
	Name   string  `json:"name"`
	Points float64 `json:"points"` // before the criticality/exposure multipliers
	Detail string  `json:"detail,omitempty"`
}

// Result is one host's blended risk.
type Result struct {
	Host        string   `json:"host"`
	Score       int      `json:"score"` // 0-100, higher is riskier
	Level       string   `json:"level"` // "low", "medium", "high", "critical"
	Criticality string   `json:"criticality"`
	Exposure    string   `json:"exposure"`
	Multiplier  float64  `json:"multiplier"`
	Factors     []Factor `json:"factors"`
}

// Criticality levels an operator can tag a host with (tag
// "criticality:<level>"); "medium" is the default when untagged.
var criticalityMultiplier = map[string]float64{"low": 0.7, "medium": 1.0, "high": 1.3, "critical": 1.6}

// CriticalityOf reads a "criticality:<level>" tag off a host's tags,
// defaulting to "medium".
func CriticalityOf(tags []string) string {
	for _, t := range tags {
		if strings.HasPrefix(t, "criticality:") {
			if lvl := strings.ToLower(strings.TrimPrefix(t, "criticality:")); criticalityMultiplier[lvl] != 0 {
				return lvl
			}
		}
	}
	return "medium"
}

// ExposureOf returns "internet" for a host tagged "exposure:internet"
// (or the plain "public" tag the demo seed already uses), otherwise
// "internal".
func ExposureOf(tags []string) string {
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "exposure:internet", "public", "internet-facing":
			return "internet"
		}
	}
	return "internal"
}

var severityPoints = map[string]float64{"critical": 30, "high": 20, "medium": 10, "low": 5}

// Compute scores one host. in carries everything else the score needs.
func Compute(in compliance.Input) Result {
	r := Result{
		Host:        in.Host.Name,
		Criticality: CriticalityOf(in.Host.Tags),
		Exposure:    ExposureOf(in.Host.Tags),
	}
	var factors []Factor

	if len(in.VulnFindings) > 0 {
		pts := 0.0
		worst := ""
		for _, f := range in.VulnFindings {
			pts += severityPoints[strings.ToLower(f.Severity)]
			if severityPoints[strings.ToLower(f.Severity)] > severityPoints[worst] {
				worst = strings.ToLower(f.Severity)
			}
		}
		if pts > 50 {
			pts = 50
		}
		factors = append(factors, Factor{Name: "vulnerabilities", Points: pts, Detail: fmt.Sprintf("%d finding(s), worst severity %s", len(in.VulnFindings), worst)})
	}
	if deficit := 100 - in.Posture.Score; deficit > 0 {
		factors = append(factors, Factor{Name: "posture", Points: float64(deficit) * 0.3, Detail: fmt.Sprintf("posture score %d", in.Posture.Score)})
	}
	if in.Stale {
		factors = append(factors, Factor{Name: "stale", Points: 10, Detail: "host hasn't reported inside the staleness window"})
	}
	if n := len(in.ShadowAIViolations); n > 0 {
		pts := float64(n) * 5
		if pts > 15 {
			pts = 15
		}
		factors = append(factors, Factor{Name: "shadow-ai", Points: pts, Detail: fmt.Sprintf("%d unsanctioned AI tool(s)", n)})
	}
	switch in.OSLifecycle.State {
	case "eol":
		factors = append(factors, Factor{Name: "os-end-of-life", Points: 15, Detail: in.OSLifecycle.Detail})
	case "ending-soon":
		factors = append(factors, Factor{Name: "os-support-ending", Points: 5, Detail: in.OSLifecycle.Detail})
	}
	if p := certs.Problems(in.Certificates); len(p) > 0 {
		pts := 5.0
		if p[0].State == "expired" {
			pts = 10
		}
		factors = append(factors, Factor{Name: "certificates", Points: pts, Detail: p[0].Detail})
	}
	if n := len(browserext.Risky(in.BrowserExtensions)); n > 0 {
		pts := float64(n) * 5
		if pts > 15 {
			pts = 15
		}
		factors = append(factors, Factor{Name: "browser-extensions", Points: pts, Detail: fmt.Sprintf("%d risky browser extension(s)", n)})
	}
	if n := len(in.SoftwareViolations); n > 0 {
		pts := float64(n) * 5
		if pts > 10 {
			pts = 10
		}
		factors = append(factors, Factor{Name: "software-policy", Points: pts, Detail: fmt.Sprintf("%d allow/deny violation(s)", n)})
	}

	base := 0.0
	for _, f := range factors {
		base += f.Points
	}
	mult := criticalityMultiplier[r.Criticality]
	if r.Exposure == "internet" {
		mult *= 1.25
	}
	r.Multiplier = mult
	score := int(base*mult + 0.5)
	if score > 100 {
		score = 100
	}
	r.Score = score
	r.Level = LevelOf(score)
	r.Factors = factors
	return r
}

// LevelOf buckets a score into a named level.
func LevelOf(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// Rank sorts results riskiest first (ties by host name).
func Rank(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].Host < results[j].Host
	})
}
