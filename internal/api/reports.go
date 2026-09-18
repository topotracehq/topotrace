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
	"net/http"
	"strings"
	"time"

	"muster/internal/history"
	"muster/internal/model"
	"muster/internal/report"
)

// buildReport assembles report.Data from live signals. The audit trail
// is included only for an admin credential (same rule as GET /api/audit)
// -- a readonly key gets the report without the activity section rather
// than a 403 for the whole thing.
func (s *Server) buildReport(r *http.Request, includeAudit bool) (report.Data, error) {
	inputs, err := s.fleetInputs(r)
	if err != nil {
		return report.Data{}, err
	}
	series, _ := history.All(r.Context(), s.Store)
	var audit []model.AuditEntry
	if includeAudit {
		audit, _ = s.Store.ListAudit(r.Context(), "", 200)
	}
	return report.Build(inputs, series, audit, time.Now().UTC()), nil
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
