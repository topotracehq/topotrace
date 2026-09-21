/*******************************************************************************
 * @file         summary.go
 * @brief        Part of the TopoTrace report module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package report

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"topotrace/internal/aiquery"
)

// Summary is a plain-English executive summary of the fleet.
type Summary struct {
	Text   string `json:"text"`
	Source string `json:"source"` // "ask-topotrace" or "template"
}

const summarySystemPrompt = `You are writing the executive summary at the top of a fleet security posture report for a CISO or IT director who will not read the tables. You are given the report's data as JSON. Write 4 short paragraphs of plain prose (no bullet points, no headers, no markdown): (1) the overall state in two sentences with the headline numbers, (2) what got better or worse over the 30-day window and how fast things are being fixed, (3) the two or three hosts or findings that most need attention and why, naming them, (4) one concrete recommendation. Use only the numbers in the data; never invent a host, a CVE or a figure. Keep it under 250 words.`

// ExecutiveSummary asks Ask TopoTrace to write the summary from d, or
// falls back to a deterministic template when it isn't configured, and
// says which in Source.
func ExecutiveSummary(ctx context.Context, cfg aiquery.Config, d Data) (Summary, error) {
	if !cfg.Enabled() {
		return Summary{Text: templateSummary(d), Source: "template"}, nil
	}
	payload, err := json.Marshal(summaryInput(d))
	if err != nil {
		return Summary{}, err
	}
	text, err := aiquery.Complete(ctx, cfg, summarySystemPrompt, "Report data (JSON):\n"+string(payload), 800)
	if err != nil {
		return Summary{}, err
	}
	return Summary{Text: text, Source: "ask-topotrace"}, nil
}

// summaryInput trims Data to what the model needs (top hosts, vulns,
// headline numbers) so the prompt stays small and the model can't
// wander off into the audit trail.
func summaryInput(d Data) map[string]any {
	top := d.Hosts
	if len(top) > 8 {
		top = top[:8]
	}
	vulns := d.Vulns
	if len(vulns) > 12 {
		vulns = vulns[:12]
	}
	in := map[string]any{
		"generated_at": d.GeneratedAt, "total_hosts": d.TotalHosts,
		"avg_posture": d.AvgPosture, "avg_compliance": d.AvgCompliance, "avg_risk": d.AvgRisk,
		"critical_risk_hosts": d.Critical, "high_risk_hosts": d.High,
		"hosts_with_vulns": d.WithVulns, "hosts_with_shadow_ai": d.WithShadowAI, "stale_hosts": d.Stale,
		"mttr":           map[string]any{"mean_hours": d.MTTR.MeanHours, "resolved": d.MTTR.Resolved, "still_open": d.MTTR.StillOpen},
		"top_risk_hosts": top, "vulnerabilities": vulns,
	}
	if len(d.Trend) > 0 {
		in["trend"] = map[string]any{
			"from": d.Trend[0].At, "to": d.Trend[len(d.Trend)-1].At,
			"posture_from": d.Trend[0].AvgPosture, "posture_to": d.Trend[len(d.Trend)-1].AvgPosture,
			"compliance_from": d.Trend[0].AvgCompliance, "compliance_to": d.Trend[len(d.Trend)-1].AvgCompliance,
		}
	}
	return in
}

// templateSummary is the no-API-key fallback: the same four paragraphs
// the model is asked for, filled from the numbers directly.
func templateSummary(d Data) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TopoTrace is managing %d hosts. The fleet's average posture score is %d out of 100 and average compliance is %d%%; %d host(s) are at critical risk and %d at high risk, %d have at least one known vulnerability, %d have unsanctioned AI tools installed, and %d have not reported inside the staleness window.\n\n",
		d.TotalHosts, d.AvgPosture, d.AvgCompliance, d.Critical, d.High, d.WithVulns, d.WithShadowAI, d.Stale)
	if len(d.Trend) > 1 {
		f, l := d.Trend[0], d.Trend[len(d.Trend)-1]
		dir := "held steady"
		if l.AvgPosture > f.AvgPosture {
			dir = "improved"
		} else if l.AvgPosture < f.AvgPosture {
			dir = "declined"
		}
		fmt.Fprintf(&b, "Over the last 30 days average posture %s from %d to %d and average compliance moved from %d%% to %d%%. ", dir, f.AvgPosture, l.AvgPosture, f.AvgCompliance, l.AvgCompliance)
	}
	if d.MTTR.Resolved > 0 {
		fmt.Fprintf(&b, "%d compliance issue(s) were resolved in the window with a mean time to remediate of %.1f days; %d remain open.\n\n", d.MTTR.Resolved, d.MTTR.MeanHours/24, d.MTTR.StillOpen)
	} else {
		fmt.Fprintf(&b, "No compliance issues were resolved in the window; %d remain open.\n\n", d.MTTR.StillOpen)
	}
	n := 3
	if len(d.Hosts) < n {
		n = len(d.Hosts)
	}
	if n > 0 {
		b.WriteString("The hosts most in need of attention are ")
		for i := 0; i < n; i++ {
			h := d.Hosts[i]
			if i > 0 {
				if i == n-1 {
					b.WriteString(", and ")
				} else {
					b.WriteString(", ")
				}
			}
			why := []string{}
			if h.Vulns > 0 {
				why = append(why, fmt.Sprintf("%d known vulnerabilit%s", h.Vulns, plural(h.Vulns, "y", "ies")))
			}
			if h.Stale {
				why = append(why, "stale")
			}
			if h.ShadowAI > 0 {
				why = append(why, "unsanctioned AI tools")
			}
			if h.Posture < 70 {
				why = append(why, fmt.Sprintf("posture %d", h.Posture))
			}
			if h.Criticality != "medium" {
				why = append(why, "criticality "+h.Criticality)
			}
			fmt.Fprintf(&b, "%s (risk %d, %s)", h.Host, h.Risk, strings.Join(why, ", "))
		}
		b.WriteString(".\n\n")
	}
	switch {
	case d.WithVulns > 0:
		fmt.Fprintf(&b, "Recommended first step: patch the %d host(s) carrying known-vulnerable packages, starting with the highest-risk ones above, then re-run the report to confirm the risk numbers drop.", d.WithVulns)
	case d.Stale > 0:
		fmt.Fprintf(&b, "Recommended first step: find out why %d host(s) have stopped reporting -- a stale host is one whose real state is unknown.", d.Stale)
	default:
		b.WriteString("Recommended first step: keep the evaluator running and watch the trend; nothing on the fleet needs urgent attention right now.")
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
