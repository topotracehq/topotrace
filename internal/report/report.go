/*******************************************************************************
 * @file         report.go
 * @brief        Package report turns the fleet's live signals into things an operator can hand to someone who will never open the dashboard: CSV exports (compliance, vulnerabilities, risk, audit) and a print-ready HTML executive summary.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package report turns the fleet's live signals into things an operator
// can hand to someone who will never open the dashboard: CSV exports
// (compliance, vulnerabilities, risk, audit) and a print-ready HTML
// executive summary. No PDF library is involved -- the HTML page is
// laid out for the browser's own print-to-PDF, which every browser
// has, instead of pulling in a rendering dependency this project would
// then own forever. Everything here is built from the same
// compliance.Input signals the dashboard uses, so a report never
// disagrees with the screen it was generated from.
package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"time"

	"muster/internal/compliance"
	"muster/internal/history"
	"muster/internal/model"
	"muster/internal/risk"
	"muster/internal/webui"
)

// HostRow is one host's line in the compliance/risk exports and the
// executive summary's table.
type HostRow struct {
	Host        string
	Platform    string
	Group       string
	Posture     int
	Compliance  int
	Risk        int
	RiskLevel   string
	Vulns       int
	ShadowAI    int
	Violations  int
	Stale       bool
	LastCooked  time.Time
	Criticality string
	Exposure    string
}

// VulnRow is one finding in the vulnerabilities export.
type VulnRow struct {
	Host, Package, Version, CVE, Severity, Description string
	// Source is "" for TopoTrace's own package-version match, or the
	// scanner an imported finding came from (see internal/scanner).
	Source string
}

// Data is everything a report can draw on, built once by Build.
type Data struct {
	Technical     bool
	ScopeNote     string
	Demo          bool
	Logo          template.URL
	NextSteps     []string
	GeneratedAt   time.Time
	Hosts         []HostRow
	Vulns         []VulnRow
	Audit         []model.AuditEntry
	Trend         []history.Bucket
	MTTR          history.MTTR
	TotalHosts    int
	AvgPosture    int
	AvgCompliance int
	AvgRisk       int
	Stale         int
	WithVulns     int
	WithShadowAI  int
	Critical      int
	High          int
}

// Build assembles Data from per-host inputs plus the optional history
// and audit slices (nil is fine for either).
func Build(inputs []compliance.Input, series []history.Series, audit []model.AuditEntry, now time.Time) Data {
	d := Data{GeneratedAt: now, Audit: audit, TotalHosts: len(inputs)}
	sumP, sumC, sumR := 0, 0, 0
	for _, in := range inputs {
		comp := compliance.Baseline.Evaluate(in)
		rk := risk.Compute(in)
		row := HostRow{
			Host: in.Host.Name, Platform: in.Host.Platform, Group: in.Host.Group,
			Posture: in.Posture.Score, Compliance: comp.Score, Risk: rk.Score, RiskLevel: rk.Level,
			Vulns: len(in.VulnFindings), ShadowAI: len(in.ShadowAIViolations), Violations: len(in.SoftwareViolations),
			Stale: in.Stale, LastCooked: in.Host.LastCooked, Criticality: rk.Criticality, Exposure: rk.Exposure,
		}
		d.Hosts = append(d.Hosts, row)
		sumP += row.Posture
		sumC += row.Compliance
		sumR += row.Risk
		if row.Stale {
			d.Stale++
		}
		if row.Vulns > 0 {
			d.WithVulns++
		}
		if row.ShadowAI > 0 {
			d.WithShadowAI++
		}
		switch rk.Level {
		case "critical":
			d.Critical++
		case "high":
			d.High++
		}
		for _, f := range in.VulnFindings {
			d.Vulns = append(d.Vulns, VulnRow{Host: in.Host.Name, Package: f.Package, Version: f.Version, CVE: f.CVE, Severity: f.Severity, Description: f.Description, Source: f.Source})
		}
	}
	if n := len(inputs); n > 0 {
		d.AvgPosture, d.AvgCompliance, d.AvgRisk = sumP/n, sumC/n, sumR/n
	}
	sort.Slice(d.Hosts, func(i, j int) bool {
		if d.Hosts[i].Risk != d.Hosts[j].Risk {
			return d.Hosts[i].Risk > d.Hosts[j].Risk
		}
		return d.Hosts[i].Host < d.Hosts[j].Host
	})
	if series != nil {
		d.Trend = history.FleetRollup(series, now, 30*24*time.Hour, 24*time.Hour)
		d.MTTR = history.TimeToRemediate(series, now, 30*24*time.Hour)
	}
	return d
}

// CSV renders one named export: "compliance", "vulnerabilities",
// "risk", or "audit". Unknown names return an error.
func CSV(d Data, name string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	switch name {
	case "compliance":
		w.Write([]string{"host", "platform", "group", "posture_score", "compliance_score", "vulnerabilities", "shadow_ai", "software_violations", "stale", "last_reported"})
		for _, h := range d.Hosts {
			w.Write([]string{h.Host, h.Platform, h.Group, strconv.Itoa(h.Posture), strconv.Itoa(h.Compliance), strconv.Itoa(h.Vulns), strconv.Itoa(h.ShadowAI), strconv.Itoa(h.Violations), strconv.FormatBool(h.Stale), h.LastCooked.UTC().Format(time.RFC3339)})
		}
	case "risk":
		w.Write([]string{"host", "risk_score", "risk_level", "criticality", "exposure", "posture_score", "compliance_score", "vulnerabilities"})
		for _, h := range d.Hosts {
			w.Write([]string{h.Host, strconv.Itoa(h.Risk), h.RiskLevel, h.Criticality, h.Exposure, strconv.Itoa(h.Posture), strconv.Itoa(h.Compliance), strconv.Itoa(h.Vulns)})
		}
	case "vulnerabilities":
		w.Write([]string{"host", "package", "installed_version", "cve", "severity", "source", "description"})
		for _, v := range d.Vulns {
			source := v.Source
			if source == "" {
				source = "muster"
			}
			w.Write([]string{v.Host, v.Package, v.Version, v.CVE, v.Severity, source, v.Description})
		}
	case "audit":
		w.Write([]string{"id", "created_at", "actor", "action", "target", "detail"})
		for _, a := range d.Audit {
			w.Write([]string{a.ID, a.CreatedAt.UTC().Format(time.RFC3339), a.Actor, a.Action, a.Target, a.Detail})
		}
	default:
		return nil, fmt.Errorf("report: unknown export %q (want compliance, risk, vulnerabilities, or audit)", name)
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// Names lists the CSV exports CSV understands.
var Names = []string{"compliance", "risk", "vulnerabilities", "audit"}

// HTML renders the print-ready executive summary.
func HTML(d Data) ([]byte, error) {
	d.Logo = template.URL(webui.ProductLogo()) // trusted embedded asset, never user input
	if d.Stale > 0 {
		d.NextSteps = append(d.NextSteps, fmt.Sprintf("Restore reporting on %d stale devices before relying on their scores.", d.Stale))
	}
	if d.Critical+d.High > 0 {
		d.NextSteps = append(d.NextSteps, fmt.Sprintf("Assign owners and deadlines to the %d high or critical risk devices.", d.Critical+d.High))
	}
	if d.WithVulns > 0 {
		d.NextSteps = append(d.NextSteps, fmt.Sprintf("Validate vulnerability matches on %d devices and schedule a tested remediation pilot.", d.WithVulns))
	}
	if len(d.NextSteps) == 0 {
		d.NextSteps = append(d.NextSteps, "Review evidence coverage and missing collections; low reported risk does not prove a complete assessment.")
	}
	d.NextSteps = append(d.NextSteps, "Confirm backups and recovery instructions before changes, then verify the result with fresh device evidence.")
	var buf bytes.Buffer
	if err := execTemplate.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var funcs = template.FuncMap{
	"date": func(t time.Time) string { return t.UTC().Format("Jan 2, 2006 15:04 UTC") },
	"day":  func(t time.Time) string { return t.UTC().Format("Jan 2") },
	"hours": func(h float64) string {
		if h == 0 {
			return "n/a"
		}
		if h < 48 {
			return fmt.Sprintf("%.0fh", h)
		}
		return fmt.Sprintf("%.1fd", h/24)
	},
	"pct": func(n, total int) string {
		if total == 0 {
			return "0%"
		}
		return fmt.Sprintf("%d%%", n*100/total)
	},
	"first": func(b []history.Bucket) history.Bucket {
		if len(b) == 0 {
			return history.Bucket{}
		}
		return b[0]
	},
	"last": func(b []history.Bucket) history.Bucket {
		if len(b) == 0 {
			return history.Bucket{}
		}
		return b[len(b)-1]
	},
	"top": func(rows []HostRow, n int) []HostRow {
		if len(rows) > n {
			return rows[:n]
		}
		return rows
	},
	"topAudit": func(rows []model.AuditEntry, n int) []model.AuditEntry {
		if len(rows) > n {
			return rows[:n]
		}
		return rows
	},
}

var execTemplate = template.Must(template.New("exec").Funcs(funcs).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TopoTrace posture report</title>
<style>
  *{box-sizing:border-box}body{font:14px/1.7 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;color:#233440;background:#f4f6f8;margin:0;padding:40px 24px}.report-page{max-width:1040px;margin:auto;padding:44px;background:white;border:1px solid #dfe5e9;border-radius:14px}.report-head{display:flex;gap:28px;align-items:center;border-bottom:2px solid #9a3e08;padding-bottom:24px;margin-bottom:28px}.report-logo{width:120px;height:120px;object-fit:contain;flex:none}.eyebrow{font-size:10px;letter-spacing:.15em;color:#9a3e08;font-weight:700;text-transform:uppercase}h1{font-size:32px;letter-spacing:-.04em;line-height:1.2;margin:8px 0}h2{font-size:18px;letter-spacing:-.02em;margin:32px 0 12px;break-after:avoid}p{margin:10px 0}.meta{color:#60717d;font-size:12px}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:28px 0}.stat{border:1px solid #dfe5e9;border-radius:9px;padding:18px;background:#f8fafb;break-inside:avoid}.stat b{display:block;font-size:28px;line-height:1.3;letter-spacing:-.03em;font-variant-numeric:tabular-nums}.stat span{font-size:11px;color:#60717d;display:block;margin-top:8px}table{border-collapse:collapse;width:100%;font-size:11px;table-layout:fixed}th,td{text-align:left;padding:10px 7px;border-bottom:1px solid #dfe5e9;overflow-wrap:anywhere;vertical-align:top}th{color:#60717d;font-size:10px;background:#f4f6f8}tr{break-inside:avoid}.warn{color:#a12d3a;font-weight:600}.ok{color:#26754b}.print{display:block;margin:0 0 22px auto;padding:10px 16px;border:1px solid #dfe5e9;border-radius:7px;background:white;color:#233440;cursor:pointer;font:inherit;font-size:12px}.demo-note{padding:14px 18px;background:#fff8e6;border:1px solid #e7d59e;border-radius:8px;color:#71551d;font-size:12px;font-weight:600}footer{border-top:1px solid #dfe5e9;padding-top:18px;margin-top:32px}@media(max-width:650px){body{padding:12px}.report-page{padding:22px}.report-head{gap:16px}.report-logo{width:70px;height:70px}h1{font-size:25px}.stats{grid-template-columns:repeat(2,1fr)}table{font-size:10px}th,td{padding:7px 4px}}@media print{@page{margin:15mm}body{background:white;padding:0;font-size:11px}.report-page{border:0;padding:0;max-width:none}.print{display:none}.report-head{break-inside:avoid}.stats{grid-template-columns:repeat(4,minmax(0,1fr))}.stat{padding:12px}.stat b{font-size:23px}table{font-size:9px}th,td{padding:7px 5px}thead{display:table-header-group}h2{break-after:avoid}}
</style></head><body>
<main class="report-page">
<button class="print" onclick="window.print()">Print / save as PDF</button>
<header class="report-head"><img class="report-logo" src="{{.Logo}}" alt="TopoTrace" width="120" height="120"><div><span class="eyebrow">TopoTrace / {{if .Technical}}Technical{{else}}Executive{{end}} report</span><h1>Fleet posture report</h1><p class="meta">McGinnis Technologies, LLC · Turn Infrastructure Into Insight</p></div></header>
{{if .ScopeNote}}<p class="meta">{{.ScopeNote}}</p>{{end}}
{{if .Demo}}<p class="demo-note">DEMO DATA — Fictional devices; not an assessment of live systems.</p>{{end}}
<div class="meta">Generated {{date .GeneratedAt}} by TopoTrace · {{.TotalHosts}} managed hosts · illustrative checks, not a certified audit</div>
<section style="clear:both"><h2>Executive summary</h2>
<p>This snapshot covers {{.TotalHosts}} managed devices. {{.Critical}} are rated critical and {{.High}} high risk. {{.Stale}} have outdated reporting, and {{.WithVulns}} have known vulnerability matches requiring validation.</p>
<h2>Recommended next steps</h2><ol>{{range .NextSteps}}<li>{{.}}</li>{{end}}</ol></section>

<div class="stats">
  <div class="stat"><b>{{.AvgPosture}}</b><span>average posture score</span></div>
  <div class="stat"><b>{{.AvgCompliance}}%</b><span>average compliance</span></div>
  <div class="stat"><b>{{.AvgRisk}}</b><span>average risk (higher is riskier)</span></div>
  <div class="stat"><b>{{.Critical}} / {{.High}}</b><span>critical / high risk hosts</span></div>
  <div class="stat"><b>{{.WithVulns}}</b><span>hosts with known vulnerabilities ({{pct .WithVulns .TotalHosts}})</span></div>
  <div class="stat"><b>{{.WithShadowAI}}</b><span>hosts with Shadow AI ({{pct .WithShadowAI .TotalHosts}})</span></div>
  <div class="stat"><b>{{.Stale}}</b><span>stale hosts</span></div>
  <div class="stat"><b>{{hours .MTTR.MeanHours}}</b><span>mean time to remediate (30d, {{.MTTR.Resolved}} resolved, {{.MTTR.StillOpen}} open)</span></div>
</div>

{{if .Trend}}<h2>30-day trend</h2>
<p>Average posture {{(first .Trend).AvgPosture}} → {{(last .Trend).AvgPosture}}, average compliance {{(first .Trend).AvgCompliance}}% → {{(last .Trend).AvgCompliance}}% ({{day (first .Trend).At}} to {{day (last .Trend).At}}).</p>{{end}}

{{if .Hosts}}<h2>{{if .Technical}}Device details{{else}}Highest-risk hosts{{end}}</h2>
<table><tr><th>Host</th><th>Platform</th><th>Group</th><th>Risk</th><th>Posture</th><th>Compliance</th><th>Vulns</th><th>Shadow AI</th><th>Stale</th></tr>
{{$rows := top .Hosts 10}}{{if .Technical}}{{$rows = .Hosts}}{{end}}
{{range $rows}}<tr><td>{{.Host}}</td><td>{{.Platform}}</td><td>{{.Group}}</td><td class="{{if or (eq .RiskLevel "critical") (eq .RiskLevel "high")}}warn{{end}}">{{.Risk}} {{.RiskLevel}}</td><td>{{.Posture}}</td><td>{{.Compliance}}%</td><td>{{.Vulns}}</td><td>{{.ShadowAI}}</td><td>{{if .Stale}}<span class="warn">yes</span>{{else}}no{{end}}</td></tr>{{end}}
</table>{{end}}

{{if .Vulns}}<h2>Known vulnerabilities ({{len .Vulns}})</h2>
<table><tr><th>Host</th><th>Package</th><th>Version</th><th>CVE</th><th>Severity</th><th>Source</th></tr>
{{range .Vulns}}<tr><td>{{.Host}}</td><td>{{.Package}}</td><td>{{.Version}}</td><td>{{.CVE}}</td><td class="{{if or (eq .Severity "critical") (eq .Severity "high")}}warn{{end}}">{{.Severity}}</td><td>{{with .Source}}{{.}}{{else}}muster{{end}}</td></tr>{{end}}
</table>{{end}}

{{if .Audit}}<h2>Recent activity</h2>
<table><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr>
{{range topAudit .Audit 15}}<tr><td>{{date .CreatedAt}}</td><td>{{.Actor}}</td><td>{{.Action}}</td><td>{{.Target}}</td><td>{{.Detail}}</td></tr>{{end}}
</table>{{end}}

<p class="meta" style="margin-top:28px">Scores are TopoTrace's own illustrative computations (see docs/compliance.md); this report is a snapshot of the dashboard's data at generation time, not a certified assessment.</p>
<footer class="meta" style="margin-top:28px;border-top:1px solid #e4e1d8;padding-top:14px">&copy; 2022–2026 McGinnis Technologies, LLC. Provided without warranty to the extent permitted by law. Verify findings and maintain backups before making changes. See Disclaimer &amp; Responsible Use in the TopoTrace dashboard.</footer>
</main></body></html>`))
