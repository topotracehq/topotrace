/*******************************************************************************
 * @file         alerts.go
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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"muster/internal/alerts"
	"muster/internal/remediate"
	"muster/internal/webhook"
)

// handleListAlerts is GET /api/alerts -- every currently open policy/
// software violation the evaluator is tracking, with first-seen,
// occurrence count and snooze state (see internal/alerts). This is the
// deduplicated "what's wrong right now" view; the audit trail keeps
// the announcements.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	state, err := alerts.Load(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "loading alert state")
		return
	}
	now := time.Now().UTC()
	list := state.List()
	type row struct {
		alerts.Violation
		Snoozed bool `json:"snoozed"`
	}
	out := make([]row, 0, len(list))
	snoozed := 0
	for _, v := range list {
		sn := v.Snoozed(now)
		if sn {
			snoozed++
		}
		out = append(out, row{Violation: v, Snoozed: sn})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"open":                len(list),
		"snoozed":             snoozed,
		"realert_after_hours": int(alerts.RealertAfter.Hours()),
		"violations":          out,
	})
}

// handleSnoozeAlert is POST /api/alerts/snooze -- body {"key": "...",
// "hours": N} (N <= 0 clears the snooze). `remediate` or higher,
// strictly: quieting an alert is an operator decision worth
// attributing.
func (s *Server) handleSnoozeAlert(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "remediate")
	if !ok {
		return
	}
	var req struct {
		Key   string  `json:"key"`
		Hours float64 `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		s.writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	state, err := alerts.Load(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "loading alert state")
		return
	}
	now := time.Now().UTC()
	var found bool
	var detail string
	if req.Hours <= 0 {
		found = state.Unsnooze(req.Key)
		detail = "snooze cleared for " + req.Key
	} else {
		if req.Hours > 24*30 {
			req.Hours = 24 * 30
		}
		found = state.Snooze(req.Key, actor, time.Duration(req.Hours*float64(time.Hour)), now)
		detail = fmt.Sprintf("snoozed %s for %.0f hour(s)", req.Key, req.Hours)
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "no open violation with that key")
		return
	}
	if err := alerts.Save(r.Context(), s.Store, state); err != nil {
		s.writeError(w, http.StatusInternalServerError, "saving alert state")
		return
	}
	v := state.Open[req.Key]
	if _, err := s.Store.RecordAudit(r.Context(), actor, "alert-snoozed", v.Host, detail); err != nil {
		s.log().Error("alerts: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, v)
}

// handleListApprovals is GET /api/approvals -- auto-remediations parked
// by rules with require_approval, oldest first.
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	list, err := alerts.ListApprovals(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing approvals")
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

// handleDecideApproval is POST /api/approvals/{id}/{decision} where
// decision is "approve" (queue the action exactly as the rule proposed
// it, through the same remediate.Validate gate every other path uses)
// or "reject" (drop it; the rule will propose again if the violation
// is still there after the pending record is gone -- so a rejection
// is "not now," and the snooze on the alert itself is "not for a
// while"). `remediate` or higher, strictly, same as queuing an action
// by hand.
func (s *Server) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "remediate")
	if !ok {
		return
	}
	id := r.PathValue("id")
	decision := r.PathValue("decision")
	if decision != "approve" && decision != "reject" {
		s.writeError(w, http.StatusBadRequest, "decision must be approve or reject")
		return
	}
	a, found, err := alerts.GetApproval(r.Context(), s.Store, id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "loading approval")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "no such pending approval")
		return
	}
	if decision == "reject" {
		if err := alerts.RemoveApproval(r.Context(), s.Store, id); err != nil {
			s.writeError(w, http.StatusInternalServerError, "removing approval")
			return
		}
		detail := fmt.Sprintf("rejected %s %s proposed by rule %q", a.Verb, a.Arg, a.RuleName)
		if _, err := s.Store.RecordAudit(r.Context(), actor, "remediation-rejected", a.Host, detail); err != nil {
			s.log().Error("approvals: recording audit entry", "err", err)
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"id": id, "decision": "rejected"})
		return
	}
	host, ok, err := s.Store.GetHost(r.Context(), a.Host)
	if err != nil || !ok {
		s.writeError(w, http.StatusNotFound, "host no longer exists")
		return
	}
	if err := remediate.Validate(host.Platform, a.Verb, a.Arg); err != nil {
		s.writeError(w, http.StatusBadRequest, "proposed action is no longer valid: "+err.Error())
		return
	}
	action, err := s.Store.QueueAction(r.Context(), a.Host, a.Verb, a.Arg)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "queuing action")
		return
	}
	if err := alerts.RemoveApproval(r.Context(), s.Store, id); err != nil {
		s.log().Error("approvals: removing approved record", "err", err)
	}
	detail := fmt.Sprintf("approved rule %q's proposal, queued action %s (%s %s)", a.RuleName, action.ID, a.Verb, a.Arg)
	if _, err := s.Store.RecordAudit(r.Context(), actor, "remediation-approved", a.Host, detail); err != nil {
		s.log().Error("approvals: recording audit entry", "err", err)
	}
	if s.Webhooks != nil {
		go s.Webhooks.Send(webhook.Event{Type: "remediation_executed", Host: a.Host, Detail: detail})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"id": id, "decision": "approved", "action": action})
}
