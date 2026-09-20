/*******************************************************************************
 * @file         benchmark.go
 * @brief        Package benchmark compares a fleet's headline numbers against a static reference baseline, so the Fleet tab can answer "how do we compare?" -- a question every security review asks and a snapshot of one fleet can't answer on its own.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package benchmark compares a fleet's headline numbers against a
// static reference baseline, so the Fleet tab can answer "how do we
// compare?" -- a question every security review asks and a snapshot of
// one fleet can't answer on its own.
//
// Stated plainly: Reference is an ILLUSTRATIVE baseline, hand-authored
// to be plausible for a mid-sized mixed Linux/Windows/macOS fleet with an
// average security program. It is not survey data, not drawn from any
// published report, and not a claim about any real industry. A real
// product would license or collect a real dataset and version it; this
// is the seam where that would plug in (swap Reference, keep Compare).
package benchmark

import (
	"fmt"
	"math"
)

// Metric is one comparable number.
type Metric struct {
	Key      string  `json:"key"`
	Label    string  `json:"label"`
	Fleet    float64 `json:"fleet"`
	Baseline float64 `json:"baseline"`
	Unit     string  `json:"unit"` // "score", "percent", "hours"
	// HigherIsBetter says which direction "good" is, so Delta can be
	// read as better/worse without the reader knowing the metric.
	HigherIsBetter bool    `json:"higher_is_better"`
	Delta          float64 `json:"delta"`  // fleet - baseline
	Better         bool    `json:"better"` // fleet is on the good side of baseline
	Summary        string  `json:"summary"`
}

// Fleet is the set of fleet-side inputs Compare needs.
type Fleet struct {
	AvgPosture    float64
	AvgCompliance float64
	PctWithVulns  float64 // 0-100
	PctStale      float64 // 0-100
	PctShadowAI   float64 // 0-100
	MTTRHours     float64 // 0 when unmeasured
	MTTRMeasured  bool
}

// Reference is the illustrative baseline -- see the package doc.
var Reference = Fleet{
	AvgPosture:    74,
	AvgCompliance: 71,
	PctWithVulns:  31,
	PctStale:      9,
	PctShadowAI:   22,
	MTTRHours:     9.5 * 24,
	MTTRMeasured:  true,
}

// Name labels the baseline in API responses and the UI.
const Name = "Illustrative reference baseline (not survey data)"

// Compare lines f up against Reference.
func Compare(f Fleet) []Metric {
	ms := []Metric{
		metric("avg_posture", "Average posture score", f.AvgPosture, Reference.AvgPosture, "score", true),
		metric("avg_compliance", "Average compliance score", f.AvgCompliance, Reference.AvgCompliance, "score", true),
		metric("pct_with_vulns", "Hosts with known vulnerabilities", f.PctWithVulns, Reference.PctWithVulns, "percent", false),
		metric("pct_stale", "Stale hosts", f.PctStale, Reference.PctStale, "percent", false),
		metric("pct_shadow_ai", "Hosts with Shadow AI", f.PctShadowAI, Reference.PctShadowAI, "percent", false),
	}
	if f.MTTRMeasured {
		ms = append(ms, metric("mttr_hours", "Mean time to remediate", f.MTTRHours, Reference.MTTRHours, "hours", false))
	}
	return ms
}

func metric(key, label string, fleet, base float64, unit string, higherBetter bool) Metric {
	m := Metric{Key: key, Label: label, Fleet: round1(fleet), Baseline: round1(base), Unit: unit, HigherIsBetter: higherBetter}
	m.Delta = round1(fleet - base)
	if higherBetter {
		m.Better = fleet >= base
	} else {
		m.Better = fleet <= base
	}
	word := "better than"
	if !m.Better {
		word = "worse than"
	}
	if m.Delta == 0 {
		word = "level with"
	}
	m.Summary = fmt.Sprintf("%s baseline by %s", word, fmtDelta(math.Abs(m.Delta), unit))
	if m.Delta == 0 {
		m.Summary = "level with baseline"
	}
	return m
}

func fmtDelta(v float64, unit string) string {
	switch unit {
	case "percent":
		return fmt.Sprintf("%.0f points", v)
	case "hours":
		if v >= 48 {
			return fmt.Sprintf("%.1f days", v/24)
		}
		return fmt.Sprintf("%.0f hours", v)
	default:
		return fmt.Sprintf("%.0f points", v)
	}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
