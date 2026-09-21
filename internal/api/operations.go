/*******************************************************************************
 * @file         operations.go
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
	"fmt"
	"net/http"
	"strings"
	"time"

	"topotrace/internal/operations"
	"topotrace/internal/risk"
	"topotrace/internal/store"
)

func (s *Server) registerOperations(mux *http.ServeMux) {
	s.registerWorkspace(mux)
	mux.HandleFunc("GET /api/visibility", s.handleVisibility)
	mux.HandleFunc("PUT /api/discovered-assets/{id}/review", s.handleAssetReview)
	mux.HandleFunc("GET /api/work", s.handleWork)
	mux.HandleFunc("PUT /api/work/assignment", s.handleAssignment)
	mux.HandleFunc("PUT /api/work/exception", s.handleException)
	mux.HandleFunc("DELETE /api/work/exception", s.handleException)
	mux.HandleFunc("GET /api/dynamic-groups", s.handleDynamicGroups)
	mux.HandleFunc("POST /api/dynamic-groups", s.handleDynamicGroups)
	mux.HandleFunc("DELETE /api/dynamic-groups/{id}", s.handleDeleteDynamicGroup)
	mux.HandleFunc("GET /api/change-plans", s.handlePlans)
	mux.HandleFunc("POST /api/change-plans", s.handlePlans)
	mux.HandleFunc("POST /api/change-plans/{id}/{decision}", s.handlePlanDecision)
	mux.HandleFunc("GET /api/hosts/{host}/verification", s.handleVerification)
}

func (s *Server) workflowBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		s.writeError(w, 400, "Invalid request: "+err.Error())
		return false
	}
	return true
}

func (s *Server) workflowHost(w http.ResponseWriter, r *http.Request, host string) bool {
	hosts, err := s.scopedHosts(r)
	if err != nil {
		s.writeError(w, 500, "loading hosts")
		return false
	}
	for _, h := range hosts {
		if h.Name == host {
			return true
		}
	}
	s.writeError(w, 404, "host not found in your scope")
	return false
}

func (s *Server) handleWork(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	in, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, 500, "loading fleet")
		return
	}
	queue, err := operations.Queue(r.Context(), s.Store, in, time.Now().UTC())
	if err != nil {
		s.writeError(w, 500, "loading work queue")
		return
	}
	owners, err := operations.List[operations.Assignment](r.Context(), s.Store, operations.AssignmentKind)
	if err != nil {
		s.writeError(w, 500, "loading owners")
		return
	}
	visible := map[string]bool{}
	hosts := []string{}
	for _, v := range in {
		visible[v.Host.Name] = true
		hosts = append(hosts, v.Host.Name)
	}
	filtered := []operations.Assignment{}
	for _, a := range owners {
		if visible[a.Host] {
			filtered = append(filtered, a)
		}
	}
	s.writeJSON(w, 200, map[string]any{"items": queue, "assignments": filtered, "hosts": hosts, "generated_at": time.Now().UTC()})
}

func (s *Server) validWorkID(w http.ResponseWriter, r *http.Request, host, id string) bool {
	if !s.workflowHost(w, r, host) {
		return false
	}
	if id == "host:"+host {
		return true
	}
	in, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, 500, "loading fleet")
		return false
	}
	q, err := operations.Queue(r.Context(), s.Store, in, time.Now().UTC())
	if err != nil {
		s.writeError(w, 500, "loading findings")
		return false
	}
	for _, item := range q {
		if item.ID == id && item.Host == host {
			return true
		}
	}
	s.writeError(w, 404, "finding is no longer open or does not belong to this host")
	return false
}
func (s *Server) handleAssignment(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "remediate")
	if !ok {
		return
	}
	var a operations.Assignment
	if !s.workflowBody(w, r, &a) || !s.validWorkID(w, r, a.Host, a.ID) {
		return
	}
	if len(a.Owner)+len(a.Team)+len(a.EscalateTo) > 600 {
		s.writeError(w, 400, "ownership fields are too long")
		return
	}
	a.UpdatedBy = actor
	a.EscalatedAt = nil
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	if err := operations.Save(r.Context(), s.Store, operations.AssignmentKind, a.ID, a); err != nil {
		s.writeError(w, 500, "saving assignment")
		return
	}
	s.Store.RecordAudit(r.Context(), actor, "work-assigned", a.Host, fmt.Sprintf("%s owner=%s team=%s", a.ID, a.Owner, a.Team))
	s.writeJSON(w, 200, a)
}
func (s *Server) handleException(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var e operations.Exception
	if !s.workflowBody(w, r, &e) {
		return
	}
	if !s.workflowHost(w, r, e.Host) {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	if r.Method == "DELETE" {
		old, found, err := operations.Load[operations.Exception](r.Context(), s.Store, operations.ExceptionKind, e.ID)
		if err != nil {
			s.writeError(w, 500, "loading exception")
			return
		}
		if !found || old.Host != e.Host {
			s.writeError(w, 404, "exception not found")
			return
		}
		if err := s.Store.DeleteDocument(r.Context(), operations.ExceptionKind, e.ID); err != nil {
			s.writeError(w, 500, "deleting exception")
			return
		}
	} else {
		if !s.validWorkID(w, r, e.Host, e.ID) {
			return
		}
		if strings.HasPrefix(e.ID, "host:") || strings.TrimSpace(e.Reason) == "" || len(e.Reason) > 2000 || !e.ExpiresAt.After(time.Now()) || e.ExpiresAt.After(time.Now().Add(90*24*time.Hour)) {
			s.writeError(w, 400, "a finding, reason, and expiry within 90 days are required")
			return
		}
		e.CreatedBy = actor
		if err := operations.Save(r.Context(), s.Store, operations.ExceptionKind, e.ID, e); err != nil {
			s.writeError(w, 500, "saving exception")
			return
		}
	}
	s.Store.RecordAudit(r.Context(), actor, "work-exception", e.Host, r.Method+" "+e.ID+" "+e.Reason)
	s.writeJSON(w, 200, map[string]string{"status": "saved"})
}

func (s *Server) handleDynamicGroups(w http.ResponseWriter, r *http.Request) {
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	role := "readonly"
	if r.Method == "POST" {
		role = "admin"
	}
	actor, ok := s.requireRoleStrict(w, r, role)
	if !ok {
		return
	}
	if r.Method == "POST" {
		var g operations.DynamicGroup
		if s.keyScope(r) != "" {
			s.writeError(w, 403, "dynamic group changes require an unscoped admin")
			return
		}
		if !s.workflowBody(w, r, &g) {
			return
		}
		if strings.TrimSpace(g.Name) == "" || len(g.Name) > 200 {
			s.writeError(w, 400, "group name is required (maximum 200 characters)")
			return
		}
		if err := g.Selector.Validate(); err != nil {
			s.writeError(w, 400, err.Error())
			return
		}
		g.ID = operations.ID()
		if err := operations.Save(r.Context(), s.Store, operations.GroupKind, g.ID, g); err != nil {
			s.writeError(w, 500, "saving group")
			return
		}
		s.Store.RecordAudit(r.Context(), actor, "dynamic-group-created", g.ID, g.Name)
		s.writeJSON(w, 201, g)
		return
	}
	groups, err := operations.List[operations.DynamicGroup](r.Context(), s.Store, operations.GroupKind)
	if err != nil {
		s.writeError(w, 500, "loading groups")
		return
	}
	in, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, 500, "loading hosts")
		return
	}
	out := []map[string]any{}
	now := time.Now().UTC()
	for _, g := range groups {
		members := []string{}
		for _, h := range in {
			if g.Selector.Matches(h.Host, h.Facts, risk.Compute(h).Score, now) {
				members = append(members, h.Host.Name)
			}
		}
		out = append(out, map[string]any{"id": g.ID, "name": g.Name, "selector": g.Selector, "members": members, "policy_target": "dynamic:" + g.ID})
	}
	s.writeJSON(w, 200, out)
}
func (s *Server) handleDeleteDynamicGroup(w http.ResponseWriter, r *http.Request) {
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	if s.keyScope(r) != "" {
		s.writeError(w, 403, "dynamic group changes require an unscoped admin")
		return
	}
	id := r.PathValue("id")
	rules, err := s.Store.ListRules(r.Context())
	if err != nil {
		s.writeError(w, 500, "loading policies")
		return
	}
	for _, rule := range rules {
		if rule.Group == "dynamic:"+id {
			s.writeError(w, 409, "remove policies targeting this group first")
			return
		}
	}
	if err := s.Store.DeleteDocument(r.Context(), operations.GroupKind, id); err != nil {
		if err == store.ErrDocumentNotFound {
			s.writeError(w, 404, "group not found")
		} else {
			s.writeError(w, 500, "deleting group")
		}
		return
	}
	s.Store.RecordAudit(r.Context(), actor, "dynamic-group-deleted", id, "")
	w.WriteHeader(204)
}

func (s *Server) handlePlans(w http.ResponseWriter, r *http.Request) {
	role := "readonly"
	if r.Method == "POST" {
		role = "remediate"
	}
	actor, ok := s.requireRoleStrict(w, r, role)
	if !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	if r.Method == "POST" {
		var p operations.Plan
		if !s.workflowBody(w, r, &p) {
			return
		}
		for _, h := range p.Hosts {
			if !s.workflowHost(w, r, h) {
				return
			}
		}
		if err := p.Validate(r.Context(), s.Store, time.Now().UTC()); err != nil {
			s.writeError(w, 400, err.Error())
			return
		}
		p.ID = operations.ID()
		p.CreatedBy = actor
		p.Actions = []operations.PlanAction{}
		p.Promoted = false
		p.Cancelled = false
		p.Status = "scheduled"
		p.RequirePreflight = true
		check, err := operations.Preflight(r.Context(), s.Store, p, time.Now().UTC())
		if err != nil {
			s.writeError(w, 500, "checking change safeguards")
			return
		}
		if !check.Ready {
			s.writeJSON(w, 409, map[string]any{"error": "Preflight checks failed; review current evidence and recovery instructions", "preflight": check})
			return
		}
		if err := operations.Save(r.Context(), s.Store, operations.PlanKind, p.ID, p); err != nil {
			s.writeError(w, 500, "saving plan")
			return
		}
		s.Store.RecordAudit(r.Context(), actor, "change-scheduled", p.ID, p.Name)
		s.writeJSON(w, 201, p)
		return
	}
	plans, err := operations.List[operations.Plan](r.Context(), s.Store, operations.PlanKind)
	if err != nil {
		s.writeError(w, 500, "loading plans")
		return
	}
	hosts, err := s.scopedHosts(r)
	if err != nil {
		s.writeError(w, 500, "loading scope")
		return
	}
	allowed := map[string]bool{}
	for _, h := range hosts {
		allowed[h.Name] = true
	}
	out := []map[string]any{}
	for _, p := range plans {
		visible := true
		for _, h := range p.Hosts {
			if !allowed[h] {
				visible = false
			}
		}
		if !visible {
			continue
		}
		checks, err := operations.PlanChecks(r.Context(), s.Store, p, time.Now().UTC())
		if err != nil {
			s.writeError(w, 500, "loading verification")
			return
		}
		out = append(out, map[string]any{"plan": p, "checks": checks})
	}
	s.writeJSON(w, 200, out)
}
func (s *Server) handlePlanDecision(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "remediate")
	if !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	p, found, err := operations.Load[operations.Plan](r.Context(), s.Store, operations.PlanKind, r.PathValue("id"))
	if err != nil {
		s.writeError(w, 500, "loading plan")
		return
	}
	if !found {
		s.writeError(w, 404, "plan not found")
		return
	}
	for _, h := range p.Hosts {
		if !s.workflowHost(w, r, h) {
			return
		}
	}
	switch r.PathValue("decision") {
	case "cancel":
		p.Cancelled = true
		p.Status = "cancelled"
	case "promote":
		if p.Cancelled || !time.Now().Before(p.WindowEnd) {
			s.writeError(w, 409, "plan is cancelled or the window has closed")
			return
		}
		verified, err := operations.PilotVerified(r.Context(), s.Store, p, time.Now().UTC())
		if err != nil {
			s.writeError(w, 500, "checking pilot")
			return
		}
		if !verified {
			s.writeError(w, 409, "every pilot must have fresh verified evidence before promotion")
			return
		}
		p.Promoted = true
	default:
		s.writeError(w, 400, "decision must be promote or cancel")
		return
	}
	if err := operations.Save(r.Context(), s.Store, operations.PlanKind, p.ID, p); err != nil {
		s.writeError(w, 500, "saving decision")
		return
	}
	s.Store.RecordAudit(r.Context(), actor, "change-"+r.PathValue("decision"), p.ID, p.Name)
	s.writeJSON(w, 200, p)
}
func (s *Server) handleVerification(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	host := r.PathValue("host")
	if !s.workflowHost(w, r, host) {
		return
	}
	actions, err := s.Store.ListActions(r.Context(), host)
	if err != nil {
		s.writeError(w, 500, "loading actions")
		return
	}
	facts, err := s.factsByCategory(r.Context(), host)
	if err != nil {
		s.writeError(w, 500, "loading facts")
		return
	}
	out := []operations.Verification{}
	for _, a := range actions {
		out = append(out, operations.Verify(a, facts, time.Now().UTC()))
	}
	s.writeJSON(w, 200, out)
}
