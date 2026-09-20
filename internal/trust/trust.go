/*******************************************************************************
 * @file         trust.go
 * @brief        Package trust turns a host's blended risk into a yes/no another system can act on: a zero-trust gateway, an enterprise browser, a VPN concentrator or an SSO policy that wants to ask "should this device get in right now?" before it grants access.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package trust turns a host's blended risk into a yes/no another
// system can act on: a zero-trust gateway, an enterprise browser, a VPN
// concentrator or an SSO policy that wants to ask "should this device
// get in right now?" before it grants access. Muster stops being only
// a place that reports on posture and becomes a posture signal
// something else enforces -- the device-trust half of a zero-trust
// access decision.
//
// The verdict is deliberately simple and explainable: a trust score
// (100 minus internal/risk's score), a level, and the reasons, with the
// thresholds stated in the response so the calling system and the
// person reading the log see the same rule.
package trust

import (
	"fmt"
	"time"

	"muster/internal/compliance"
	"muster/internal/risk"
)

// Thresholds are the default trust-score cut-offs.
const (
	TrustedAt     = 75 // score >= TrustedAt is "trusted"
	ConditionalAt = 50 // score >= ConditionalAt is "conditional"; below is "untrusted"
)

// Verdict is what a gate gets back.
type Verdict struct {
	Host        string    `json:"host"`
	Score       int       `json:"score"` // 0-100, higher is more trustworthy
	Level       string    `json:"level"` // "trusted", "conditional", "untrusted"
	Allow       bool      `json:"allow"` // score >= the min the caller asked for
	MinScore    int       `json:"min_score"`
	Reasons     []string  `json:"reasons"`
	Stale       bool      `json:"stale"`
	LastReport  time.Time `json:"last_report"`
	EvaluatedAt time.Time `json:"evaluated_at"`
	Thresholds  struct {
		Trusted     int `json:"trusted"`
		Conditional int `json:"conditional"`
	} `json:"thresholds"`
}

// Evaluate computes the verdict from the host's signals. minScore is
// the caller's bar for Allow (0 means "use ConditionalAt").
func Evaluate(in compliance.Input, minScore int, now time.Time) Verdict {
	r := risk.Compute(in)
	v := Verdict{Host: in.Host.Name, Score: 100 - r.Score, Stale: in.Stale, LastReport: in.Host.LastCooked, EvaluatedAt: now}
	v.Thresholds.Trusted, v.Thresholds.Conditional = TrustedAt, ConditionalAt
	if minScore <= 0 {
		minScore = ConditionalAt
	}
	v.MinScore = minScore
	for _, f := range r.Factors {
		v.Reasons = append(v.Reasons, fmt.Sprintf("%s: %s", f.Name, f.Detail))
	}
	if in.Stale {
		// a host that hasn't reported can't be vouched for, whatever it
		// looked like last time -- cap it below "trusted"
		if v.Score >= TrustedAt {
			v.Score = TrustedAt - 1
		}
	}
	switch {
	case v.Score >= TrustedAt:
		v.Level = "trusted"
	case v.Score >= ConditionalAt:
		v.Level = "conditional"
	default:
		v.Level = "untrusted"
	}
	v.Allow = v.Score >= minScore
	if v.Reasons == nil {
		v.Reasons = []string{}
	}
	return v
}
