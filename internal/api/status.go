/*******************************************************************************
 * @file         status.go
 * @brief        Part of the Muster api module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"html/template"
	"net/http"
	"time"

	"muster/internal/alerts"
	"muster/internal/compliance"
	"muster/internal/history"
)

// StartedAt is stamped by cmd/muster so the status page can report
// uptime; zero means "unknown" (tests).
var StartedAt time.Time

// statusData is everything the public status page shows -- aggregates
// only, deliberately: no host names, no findings, no detail. The page
// exists so a customer, an auditor, or a manager can see that the
// program is running and roughly how healthy the fleet is without
// being handed the inventory.
type statusData struct {
	GeneratedAt      time.Time
	Uptime           string
	TotalHosts       int
	PctCompliant     int
	AvgPosture       int
	AvgCompliance    int
	OpenViolations   int
	ResolvedThisWeek int
	LastEvaluated    time.Time
	Integrations     []statusIntegration
	Overall          string // "operational", "degraded", "attention"
}

type statusIntegration struct {
	Name   string
	Status string // "on", "off"
}

func (s *Server) buildStatus(r *http.Request) statusData {
	now := time.Now().UTC()
	d := statusData{GeneratedAt: now, Overall: "operational"}
	if !StartedAt.IsZero() {
		d.Uptime = now.Sub(StartedAt).Truncate(time.Minute).String()
	}
	inputs, err := s.fleetInputs(r)
	if err == nil {
		sumP, sumC, full := 0, 0, 0
		for _, in := range inputs {
			c := compliance.Baseline.Evaluate(in)
			sumP += in.Posture.Score
			sumC += c.Score
			if c.Score == 100 {
				full++
			}
		}
		d.TotalHosts = len(inputs)
		if n := len(inputs); n > 0 {
			d.AvgPosture, d.AvgCompliance, d.PctCompliant = sumP/n, sumC/n, full*100/n
		}
	}
	if state, err := alerts.Load(r.Context(), s.Store); err == nil {
		d.OpenViolations = len(state.Open)
	}
	if all, err := history.All(r.Context(), s.Store); err == nil {
		m := history.TimeToRemediate(all, now, 7*24*time.Hour)
		d.ResolvedThisWeek = m.Resolved
		for _, srs := range all {
			if n := len(srs.Points); n > 0 && srs.Points[n-1].At.After(d.LastEvaluated) {
				d.LastEvaluated = srs.Points[n-1].At
			}
		}
	}
	on := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	d.Integrations = []statusIntegration{
		{"Background evaluator", on(!d.LastEvaluated.IsZero() && now.Sub(d.LastEvaluated) < 2*s.EvaluatorInterval+time.Minute)},
		{"Notifications", on(s.Webhooks.Count() > 0)},
		{"SIEM forwarding", on(s.SIEMForwarder != nil && s.SIEMForwarder.Configured())},
		{"Vulnerability feed", on(s.VulnFeed != nil)},
		{"Ask Muster", on(s.AIQuery != nil && s.AIQuery.Get().Enabled())},
	}
	switch {
	case d.TotalHosts > 0 && d.AvgCompliance < 50:
		d.Overall = "attention"
	case d.OpenViolations > d.TotalHosts || d.Integrations[0].Status == "off":
		d.Overall = "degraded"
	}
	return d
}

// handleStatusPage is GET /status -- unauthenticated, aggregates only.
// Disabled entirely with -public-status=false.
func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	if !s.PublicStatus {
		http.NotFound(w, r)
		return
	}
	d := s.buildStatus(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	if err := statusTemplate.Execute(w, d); err != nil {
		s.log().Error("status page", "err", err)
	}
}

// handleStatusJSON is GET /status.json -- the same aggregates as JSON.
func (s *Server) handleStatusJSON(w http.ResponseWriter, r *http.Request) {
	if !s.PublicStatus {
		http.NotFound(w, r)
		return
	}
	d := s.buildStatus(r)
	w.Header().Set("Cache-Control", "public, max-age=60")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"overall": d.Overall, "generated_at": d.GeneratedAt, "uptime": d.Uptime,
		"total_hosts": d.TotalHosts, "pct_fully_compliant": d.PctCompliant, "avg_posture": d.AvgPosture, "avg_compliance": d.AvgCompliance,
		"open_violations": d.OpenViolations, "resolved_last_7d": d.ResolvedThisWeek, "last_evaluated": d.LastEvaluated, "integrations": d.Integrations,
	})
}

var statusTemplate = template.Must(template.New("status").Funcs(template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.UTC().Format("Jan 2, 2006 15:04 UTC")
	},
}).Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Muster status</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font: 15px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #23272a; background: #f4f3ef; margin: 0; }
  main { max-width: 720px; margin: 40px auto; padding: 0 20px; }
  h1 { font-size: 22px; margin: 0 0 4px; } .meta { color: #6b7278; font-size: 13px; }
  .overall { display: inline-block; margin: 18px 0; padding: 8px 14px; border-radius: 8px; font-weight: 700; }
  .operational { background: #e6f4ea; color: #1e6b32; } .degraded { background: #fdf3d9; color: #8a6300; } .attention { background: #fdecec; color: #a33a2a; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 12px 0 24px; }
  .stat { background: #fff; border: 1px solid #e4e1d8; border-radius: 8px; padding: 12px 14px; } .stat b { display: block; font-size: 24px; } .stat span { font-size: 12px; color: #6b7278; }
  ul { list-style: none; padding: 0; margin: 0; background: #fff; border: 1px solid #e4e1d8; border-radius: 8px; }
  li { display: flex; justify-content: space-between; padding: 10px 14px; border-bottom: 1px solid #e4e1d8; } li:last-child { border-bottom: none; }
  .on { color: #1e6b32; font-weight: 600; } .off { color: #6b7278; }
  footer { margin-top: 28px; font-size: 12px; color: #6b7278; }
</style></head><body><main>
<h1>Muster fleet status</h1>
<div class="meta">Generated {{date .GeneratedAt}}{{if .Uptime}} · server up {{.Uptime}}{{end}} · refreshes every minute</div>
<div class="overall {{.Overall}}">{{if eq .Overall "operational"}}All systems operational{{else if eq .Overall "degraded"}}Degraded -- see below{{else}}Needs attention{{end}}</div>
<div class="grid">
  <div class="stat"><b>{{.TotalHosts}}</b><span>managed hosts</span></div>
  <div class="stat"><b>{{.PctCompliant}}%</b><span>fully compliant</span></div>
  <div class="stat"><b>{{.AvgPosture}}</b><span>average posture score (0-100)</span></div>
  <div class="stat"><b>{{.AvgCompliance}}%</b><span>average compliance</span></div>
  <div class="stat"><b>{{.OpenViolations}}</b><span>open policy findings</span></div>
  <div class="stat"><b>{{.ResolvedThisWeek}}</b><span>findings resolved, last 7 days</span></div>
</div>
<ul>
{{range .Integrations}}<li><span>{{.Name}}</span><span class="{{.Status}}">{{if eq .Status "on"}}operational{{else}}not configured{{end}}</span></li>{{end}}
<li><span>Last evaluation run</span><span>{{date .LastEvaluated}}</span></li>
</ul>
<footer>Aggregate figures only -- this page never lists hosts, findings, or people. Scores are Muster's own illustrative computations, not a certified assessment. Operators: the full dashboard is at <a href="/">/</a>.</footer>
</main></body></html>`))
