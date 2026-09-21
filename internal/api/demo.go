/*******************************************************************************
 * @file         demo.go
 * @brief        Part of the Muster api module.
 * @project      Muster
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
	"fmt"
	"net/http"

	"muster/internal/bookmark"
	"muster/internal/graph"
	"muster/internal/model"
	"muster/internal/store"
	"muster/internal/webhook"
)

// handleGraph is GET /api/graph -- the network/asset relationship
// picture (see internal/graph), laid out server-side.
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	inputs, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "gathering fleet signals")
		return
	}
	ifaces := map[string]model.Fact{}
	for _, in := range inputs {
		if f, ok := in.Facts["network_interfaces"]; ok {
			ifaces[in.Host.Name] = f
		}
	}
	assets, err := s.Store.ListDiscoveredAssets(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing discovered assets")
		return
	}
	s.writeJSON(w, http.StatusOK, graph.Build(inputs, ifaces, assets))
}

// --- bookmarks ("since last demo") ---------------------------------

func (s *Server) currentSnapshot(r *http.Request) (bookmark.Bookmark, error) {
	inputs, err := s.fleetInputs(r)
	if err != nil {
		return bookmark.Bookmark{}, err
	}
	rules, _ := s.Store.ListRules(r.Context())
	assets, _ := s.Store.ListDiscoveredAssets(r.Context())
	return bookmark.Snapshot(inputs, len(rules), len(assets)), nil
}

// handleListBookmarks is GET /api/bookmarks.
func (s *Server) handleListBookmarks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	list, err := bookmark.List(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing bookmarks")
		return
	}
	// the host maps are big; the list view only needs the headline
	out := make([]map[string]any, 0, len(list))
	for _, b := range list {
		out = append(out, map[string]any{"id": b.ID, "name": b.Name, "created_by": b.CreatedBy, "created_at": b.CreatedAt,
			"hosts": len(b.Hosts), "rules": b.Rules, "assets": b.Assets, "avg_posture": b.AvgPosture, "avg_risk": b.AvgRisk})
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleCreateBookmark is POST /api/bookmarks {"name": "..."} -- snapshot
// the fleet now. `remediate` or higher, strict: a bookmark is a
// deliberate operator act worth attributing.
func (s *Server) handleCreateBookmark(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "remediate")
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	snap, err := s.currentSnapshot(r)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "snapshotting fleet")
		return
	}
	b, err := bookmark.Save(r.Context(), s.Store, snap, req.Name, actor)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "saving bookmark")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "bookmark-created", b.Name, fmt.Sprintf("snapshot of %d hosts", len(b.Hosts))); err != nil {
		s.log().Error("bookmark: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"id": b.ID, "name": b.Name, "created_at": b.CreatedAt, "hosts": len(b.Hosts)})
}

// handleBookmarkDiff is GET /api/bookmarks/{id}/diff -- the bookmark
// against the fleet now.
func (s *Server) handleBookmarkDiff(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	then, found, err := bookmark.Get(r.Context(), s.Store, r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "loading bookmark")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "no such bookmark")
		return
	}
	now, err := s.currentSnapshot(r)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "snapshotting fleet")
		return
	}
	d := bookmark.Compare(then, now)
	d.Bookmark.Hosts, d.Now.Hosts = nil, nil // the diff is the point; don't ship both maps
	s.writeJSON(w, http.StatusOK, d)
}

// handleDeleteBookmark is DELETE /api/bookmarks/{id}.
func (s *Server) handleDeleteBookmark(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoleStrict(w, r, "remediate"); !ok {
		return
	}
	if err := bookmark.Delete(r.Context(), s.Store, r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrDocumentNotFound) {
			s.writeError(w, http.StatusNotFound, "no such bookmark")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "deleting bookmark")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- demo / simulator ----------------------------------------------

// demoScenarios is the fixed menu POST /api/demo/simulate accepts. Each
// pushes synthetic events through the exact paths a real one would --
// the audit trail (and therefore SIEM forwarding), the notification
// queue, the alerts state -- without waiting for a real agent to
// misbehave. Nothing here touches host facts or rules.
var demoScenarios = map[string]string{
	"policy_violation":     "a policy violation on a host (audit + notifications + SIEM)",
	"software_violation":   "a denied-software finding (audit + notifications + SIEM)",
	"remediation_proposed": "an auto-remediation waiting for approval (audit + notifications)",
	"violation_resolved":   "a violation clearing (audit + notifications)",
	"operator_burst":       "a burst of operator writes by 'demo-operator', to light up the behavioral signals",
	"admin_key":            "an admin-role API key being created by 'demo-operator' (behavioral signals)",
	"full_story":           "all of the above in sequence, a few seconds apart",
}

// handleDemoScenarios is GET /api/demo/scenarios.
func (s *Server) handleDemoScenarios(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, demoScenarios)
}

// handleDemoSimulate is POST /api/demo/simulate {"scenario": "...",
// "host": "..."} -- admin, strict: it writes audit entries and sends
// notifications on the operator's behalf. Every synthetic entry is
// marked "(simulated)" in its detail so it can never be mistaken for a
// real finding in the trail.
func (s *Server) handleDemoSimulate(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req struct {
		Scenario string `json:"scenario"`
		Host     string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || demoScenarios[req.Scenario] == "" {
		s.writeError(w, http.StatusBadRequest, "scenario must be one of the names from GET /api/demo/scenarios")
		return
	}
	host := req.Host
	if host == "" {
		if hosts, _ := s.Store.ListHosts(r.Context()); len(hosts) > 0 {
			host = hosts[0].Name
		} else {
			host = "demo-host"
		}
	}
	var fired []string
	emit := func(action, detail, eventType string) {
		detail += " (simulated)"
		if _, err := s.Store.RecordAudit(r.Context(), "system", action, host, detail); err != nil {
			s.log().Error("demo: recording audit entry", "err", err)
		}
		if eventType != "" && s.Webhooks != nil {
			s.Webhooks.Send(webhook.Event{Type: eventType, Host: host, Detail: detail})
		}
		fired = append(fired, action)
	}
	run := func(scenario string) {
		switch scenario {
		case "policy_violation":
			emit("policy-violation", `rule "Demo: posture floor": posture score 42 is below threshold 80`, "policy_violation")
		case "software_violation":
			emit("software-violation", `denied software "telnetd" (rule "Demo: ban telnet"): telnetd 0.17-45`, "software_violation")
		case "remediation_proposed":
			emit("remediation-proposed", `rule "Demo: restart on failure" proposed restart-service nginx -- waiting for approval`, "remediation_proposed")
		case "violation_resolved":
			emit("policy-resolved", `rule "Demo: posture floor" no longer violated`, "violation_resolved")
		case "operator_burst":
			for i := 0; i < 12; i++ {
				if _, err := s.Store.RecordAudit(r.Context(), "demo-operator", "delete-policy", fmt.Sprintf("rule-%d", i), "deleted policy rule (simulated)"); err != nil {
					s.log().Error("demo: recording audit entry", "err", err)
				}
			}
			fired = append(fired, "delete-policy x12 by demo-operator")
		case "admin_key":
			if _, err := s.Store.RecordAudit(r.Context(), "demo-operator", "create-key", "demo-admin", `created API key "demo-admin" with role admin (simulated)`); err != nil {
				s.log().Error("demo: recording audit entry", "err", err)
			}
			fired = append(fired, "create-key (admin) by demo-operator")
		}
	}
	if req.Scenario == "full_story" {
		for _, sc := range []string{"policy_violation", "software_violation", "remediation_proposed", "operator_burst", "admin_key", "violation_resolved"} {
			run(sc)
		}
	} else {
		run(req.Scenario)
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "demo-simulate", host, "ran scenario "+req.Scenario); err != nil {
		s.log().Error("demo: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"scenario": req.Scenario, "host": host, "fired": fired, "sinks": s.Webhooks.Count(),
		"note": "synthetic entries are marked (simulated) in the audit trail; notifications went through the real queue"})
}
