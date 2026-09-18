/*******************************************************************************
 * @file         reports.go
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
	"fmt"
	"net/http"
	"strings"
	"time"

	"muster/internal/compliance"
	"muster/internal/history"
	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/report"
	"muster/internal/signals"
)

// buildReport assembles report.Data from live signals. The audit trail
// is included only for an admin credential (same rule as GET /api/audit)
// -- a readonly key gets the report without the activity section rather
// than a 403 for the whole thing.
func (s *Server) buildReport(r *http.Request, includeAudit bool) (report.Data, error) {
	if r.URL.Query().Get("demo") == "1" {
		now := time.Now().UTC()
		st, err := visibilityDemo(now)
		if err != nil {
			return report.Data{}, err
		}
		hosts, err := st.ListHosts(r.Context())
		if err != nil {
			return report.Data{}, err
		}
		inputs := []compliance.Input{}
		for _, h := range hosts {
			in, err := signals.Gather(r.Context(), st, h, nil, nil)
			if err != nil {
				return report.Data{}, err
			}
			inputs = append(inputs, in)
		}
		d := report.Build(inputs, nil, nil, now)
		d.Demo = true
		return d, nil
	}
	inputs, err := s.fleetInputs(r)
	if err != nil {
		return report.Data{}, err
	}
	q := r.URL.Query()
	var start, end time.Time
	if q.Get("from") != "" {
		start, err = time.Parse("2006-01-02", q.Get("from"))
		if err != nil {
			return report.Data{}, fmt.Errorf("invalid start date")
		}
	}
	if q.Get("to") != "" {
		end, err = time.Parse("2006-01-02", q.Get("to"))
		if err != nil {
			return report.Data{}, fmt.Errorf("invalid end date")
		}
		end = end.Add(24 * time.Hour)
	}
	if !start.IsZero() && !end.IsZero() && !start.Before(end) {
		return report.Data{}, fmt.Errorf("invalid date range")
	}
	selected := map[string]bool{}
	if id := q.Get("collection"); id != "" {
		c, ok, e := operations.Load[deviceCollection](r.Context(), s.Store, collectionKind, id)
		if e != nil || !ok || (s.keyScope(r) != "" && c.Group != s.keyScope(r)) {
			return report.Data{}, fmt.Errorf("collection unavailable")
		}
		for _, h := range c.Hosts {
			selected[h] = true
		}
	}
	selectedInputs := inputs[:0]
	for _, in := range inputs {
		if q.Get("group") != "" && in.Host.Group != q.Get("group") {
			continue
		}
		if q.Get("collection") != "" && !selected[in.Host.Name] {
			continue
		}
		selectedInputs = append(selectedInputs, in)
	}
	inputs = selectedInputs
	series, _ := history.All(r.Context(), s.Store)
	visible := map[string]bool{}
	for _, in := range inputs {
		visible[in.Host.Name] = true
	}
	filtered := series[:0]
	for _, v := range series {
		if visible[v.Host] {
			points := v.Points[:0]
			for _, p := range v.Points {
				if (start.IsZero() || !p.At.Before(start)) && (end.IsZero() || p.At.Before(end)) {
					points = append(points, p)
				}
			}
			v.Points = points
			filtered = append(filtered, v)
		}
	}
	series = filtered
	var audit []model.AuditEntry
	if includeAudit {
		audit, _ = s.Store.ListAudit(r.Context(), "", 200)
		if s.keyScope(r) != "" || q.Get("collection") != "" || q.Get("group") != "" || !start.IsZero() || !end.IsZero() {
			filtered := audit[:0]
			for _, a := range audit {
				if visible[a.Target] && (start.IsZero() || !a.CreatedAt.Before(start)) && (end.IsZero() || a.CreatedAt.Before(end)) {
					filtered = append(filtered, a)
				}
			}
			audit = filtered
		}
	}
	d := report.Build(inputs, series, audit, time.Now().UTC())
	d.Technical = q.Get("mode") == "technical"
	d.ScopeNote = "Current inventory snapshot. Date selection filters retained trend/activity only (UTC); trends are limited to the most recent 30 days."
	if q.Get("from") != "" || q.Get("to") != "" {
		d.ScopeNote += " Requested interval: " + q.Get("from") + " through " + q.Get("to") + "."
	}
	if q.Get("sections") != "" {
		sections := "," + q.Get("sections") + ","
		if !strings.Contains(sections, ",hosts,") {
			d.Hosts = nil
		}
		if !strings.Contains(sections, ",vulnerabilities,") {
			d.Vulns = nil
		}
		if !strings.Contains(sections, ",activity,") {
			d.Audit = nil
		}
		if !strings.Contains(sections, ",trend,") {
			d.Trend = nil
		}
	}
	return d, nil
}

// isAdmin reports whether the request's credential resolves to admin,
// without writing an error response -- for "include the extra section
// if allowed" decisions inside an endpoint that's already readonly-gated.
func (s *Server) isAdmin(r *http.Request) bool {
	if s.AuthToken == "" {
		return true
	}
	rec := &discardWriter{}
	_, ok := s.requireRoleStrict(rec, r, "admin")
	return ok
}

// discardWriter swallows the error response requireRoleStrict would
// otherwise write, so isAdmin can probe without answering the request.
type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header {
	if d.h == nil {
		d.h = http.Header{}
	}
	return d.h
}
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

// handleReportCSV is GET /api/reports/{name}.csv -- name is one of
// report.Names. The audit export is admin-only; the rest are readonly.
func (s *Server) handleReportCSV(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(r.PathValue("name"), ".csv")
	need := "readonly"
	if name == "audit" {
		need = "admin"
	}
	if _, ok := s.requireRole(w, r, need); !ok {
		return
	}
	d, err := s.buildReport(r, name == "audit")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "building report")
		return
	}
	out, err := report.CSV(d, name)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="muster-`+name+`-`+d.GeneratedAt.Format("2006-01-02")+`.csv"`)
	w.Write(out)
}

// handleReportHTML is GET /api/reports/executive -- the print-ready
// executive summary as a standalone HTML page (use the browser's own
// print-to-PDF; see internal/report for why there's no PDF library).
func (s *Server) handleReportHTML(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	d, err := s.buildReport(r, s.isAdmin(r))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "building report")
		return
	}
	out, err := report.HTML(d)
	if err != nil {
		s.log().Error("rendering executive report", "err", err)
		s.writeError(w, http.StatusInternalServerError, "rendering report")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(out)
}
