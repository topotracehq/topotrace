/*******************************************************************************
 * @file         askmore.go
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
	"errors"
	"net/http"
	"strings"

	"topotrace/internal/aiquery"
	"topotrace/internal/report"
)

// aiConfig returns the live Ask TopoTrace config (zero value when the
// ConfigStore isn't wired, as in tests).
func (s *Server) aiConfig() aiquery.Config {
	if s.AIQuery == nil {
		return aiquery.Config{}
	}
	return s.AIQuery.Get()
}

// handleDraftPolicy is POST /api/ask/draft-policy -- {"description":
// "..."} in, a PolicyDraft out: the rule Ask TopoTrace (or, without a key,
// a keyword heuristic) proposes, in POST /api/policies's own field
// names, for the operator to review and create. Nothing is written:
// the draft is the AI's whole contribution, the decision is a
// person's. Readonly is enough to ask; creating the rule still needs
// admin. Recorded to the audit trail like every Ask TopoTrace call.
func (s *Server) handleDraftPolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "readonly")
	if !ok {
		return
	}
	var req struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Description) == "" {
		s.writeError(w, http.StatusBadRequest, "description is required")
		return
	}
	draft, err := aiquery.DraftPolicy(r.Context(), s.aiConfig(), req.Description)
	validation := ""
	if err != nil {
		if errors.Is(err, aiquery.ErrNotConfigured) {
			s.writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if draft.Name == "" {
			s.log().Error("draft policy", "err", err)
			s.writeError(w, http.StatusBadGateway, "Ask TopoTrace: "+err.Error())
			return
		}
		validation = err.Error() // a draft came back but doesn't fit the vocabulary -- show it anyway, flagged
	}
	detail := "drafted policy from: " + truncate(req.Description, 120) + " -> " + draft.Kind + " (" + draft.Source + ")"
	if _, err := s.Store.RecordAudit(r.Context(), actor, "ask-topotrace", "policy-draft", detail); err != nil {
		s.log().Error("draft policy: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"draft": draft, "validation_error": validation})
}

// handleExecutiveSummary is POST /api/ask/summary -- the plain-English
// executive summary of the fleet, written by Ask TopoTrace from the same
// report.Data the executive report uses, or by a template when Ask
// TopoTrace isn't configured (Source says which). Readonly; audited.
func (s *Server) handleExecutiveSummary(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "readonly")
	if !ok {
		return
	}
	d, err := s.buildReport(r, false)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "building report")
		return
	}
	sum, err := report.ExecutiveSummary(r.Context(), s.aiConfig(), d)
	if err != nil {
		s.log().Error("executive summary", "err", err)
		s.writeError(w, http.StatusBadGateway, "Ask TopoTrace: "+err.Error())
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "ask-topotrace", "executive-summary", "generated executive summary ("+sum.Source+"): "+truncate(sum.Text, 160)); err != nil {
		s.log().Error("executive summary: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"summary": sum, "generated_at": d.GeneratedAt, "total_hosts": d.TotalHosts})
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
