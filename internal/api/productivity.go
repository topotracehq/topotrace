/*******************************************************************************
 * @file         productivity.go
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
	"net/http"
	"sort"
	"strings"
	"time"

	"muster/docs"
	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/siteops"
	"muster/internal/webhook"
)

const collectionKind = "device_collection"

type deviceCollection struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Group string   `json:"group"`
	Hosts []string `json:"hosts"`
}
type attentionItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Host  string `json:"host,omitempty"`
	Link  string `json:"link"`
	Read  bool   `json:"read"`
}

func (s *Server) registerProductivity(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/overview", s.handleOverview)
	mux.HandleFunc("GET /api/search-all", s.handleSearchAll)
	mux.HandleFunc("GET /api/collections", s.handleCollections)
	mux.HandleFunc("POST /api/collections", s.handleCollections)
	mux.HandleFunc("DELETE /api/collections/{id}", s.handleCollections)
	mux.HandleFunc("GET /api/compare", s.handleCompare)
	mux.HandleFunc("PUT /api/inbox/{id}", s.handleInboxRead)
	mux.HandleFunc("GET /api/integration-health", s.handleIntegrationHealth)
}
func (s *Server) handleCollections(w http.ResponseWriter, r *http.Request) {
	role := "readonly"
	if r.Method != "GET" {
		role = "remediate"
	}
	if _, ok := s.requireRoleStrict(w, r, role); !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	hosts, err := s.scopedHosts(r)
	if err != nil {
		s.writeError(w, 500, "loading hosts")
		return
	}
	visible := map[string]bool{}
	for _, h := range hosts {
		visible[h.Name] = true
	}
	if r.Method == "POST" {
		var c deviceCollection
		if !s.workflowBody(w, r, &c) {
			return
		}
		c.Name = strings.TrimSpace(c.Name)
		if c.Name == "" || len(c.Name) > 100 || len(c.Hosts) == 0 || len(c.Hosts) > 1000 {
			s.writeError(w, 400, "provide a name and 1–1000 hosts")
			return
		}
		seen := map[string]bool{}
		for _, h := range c.Hosts {
			if !visible[h] || seen[h] {
				s.writeError(w, 400, "hosts must be unique and in your scope")
				return
			}
			seen[h] = true
		}
		c.ID = operations.ID()
		c.Group = s.keyScope(r)
		if err := operations.Save(r.Context(), s.Store, collectionKind, c.ID, c); err != nil {
			s.writeError(w, 500, "saving collection")
			return
		}
		s.writeJSON(w, 201, c)
		return
	}
	all, err := operations.List[deviceCollection](r.Context(), s.Store, collectionKind)
	if err != nil {
		s.writeError(w, 500, "loading collections")
		return
	}
	out := []deviceCollection{}
	for _, c := range all {
		if s.keyScope(r) != "" && c.Group != s.keyScope(r) {
			continue
		}
		if r.Method == "DELETE" && c.ID == r.PathValue("id") {
			if err := s.Store.DeleteDocument(r.Context(), collectionKind, c.ID); err != nil {
				s.writeError(w, 500, "deleting collection")
				return
			}
			s.writeJSON(w, 200, map[string]bool{"deleted": true})
			return
		}
		selected := []string{}
		for _, h := range c.Hosts {
			if visible[h] {
				selected = append(selected, h)
			}
		}
		c.Hosts = selected
		out = append(out, c)
	}
	if r.Method == "DELETE" {
		s.writeError(w, 404, "collection not found")
		return
	}
	s.writeJSON(w, 200, out)
}
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "readonly")
	if !ok {
		return
	}
	inputs, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, 500, "loading fleet")
		return
	}
	now := time.Now().UTC()
	items, err := operations.Queue(r.Context(), s.Store, inputs, now)
	if err != nil {
		s.writeError(w, 500, "loading findings")
		return
	}
	attention := []attentionItem{}
	stale := 0
	facts := 0
	failedChanges := 0
	newDevices := 0
	for _, in := range inputs {
		actions, e := s.Store.ListActions(r.Context(), in.Host.Name)
		if e != nil {
			s.writeError(w, 500, "loading action results")
			return
		}
		for _, a := range actions {
			if a.Status == "fail" {
				failedChanges++
				attention = append(attention, attentionItem{ID: "action:" + a.ID, Title: "Failed change: " + a.Verb, Host: in.Host.Name, Link: "#/host/" + in.Host.Name})
			}
		}
		if in.Host.LastCooked.IsZero() || now.Sub(in.Host.LastCooked) > 24*time.Hour {
			stale++
			attention = append(attention, attentionItem{ID: "stale:" + in.Host.Name, Title: "Agent report overdue", Host: in.Host.Name, Link: "#/agents"})
		} else {
			facts++
		}
	}
	for _, v := range items {
		attention = append(attention, attentionItem{ID: v.ID, Title: v.Title, Host: v.Host, Link: "#/work"})
	}
	overdue := 0
	for _, v := range items {
		if v.Overdue {
			overdue++
		}
	}
	assets := []model.DiscoveredAsset{}
	if s.keyScope(r) == "" {
		assets, err = s.Store.ListDiscoveredAssets(r.Context())
		if err != nil {
			s.writeError(w, 500, "loading discoveries")
			return
		}
		for _, a := range assets {
			if !a.Known {
				newDevices++
				attention = append(attention, attentionItem{ID: "asset:" + a.ID, Title: "Review discovered device " + a.Address, Link: "#/visibility"})
			}
		}
	}
	if s.keyScope(r) == "" {
		sightings, e := operations.List[siteops.Sighting](r.Context(), s.Store, siteops.SightingKind)
		if e != nil {
			s.writeError(w, 500, "loading site discoveries")
			return
		}
		for _, v := range sightings {
			if v.Review == "new" {
				newDevices++
				attention = append(attention, attentionItem{ID: "site:" + v.ID, Title: "Review discovered device " + v.Address, Link: "#/discovery"})
			}
		}
		jobs, e := operations.List[siteops.Job](r.Context(), s.Store, siteops.JobKind)
		if e != nil {
			s.writeError(w, 500, "loading deployment jobs")
			return
		}
		for _, j := range jobs {
			if j.Phase == "failed" || j.Phase == "uncertain" {
				attention = append(attention, attentionItem{ID: "job:" + j.ID, Title: j.Name + " requires attention (" + j.Phase + ")", Link: "#/discovery"})
			}
		}
	}
	for i := range attention {
		_, found, e := s.Store.GetDocument(r.Context(), "inbox_read", sha256Hex(actor+"\x00"+s.keyScope(r)+"\x00"+attention[i].ID))
		if e != nil {
			s.writeError(w, 500, "loading inbox")
			return
		}
		attention[i].Read = found
	}
	s.writeJSON(w, 200, map[string]any{"hosts": len(inputs), "reporting": facts, "stale": stale, "findings": len(items), "overdue": overdue, "discoveries": newDevices, "failed_changes": failedChanges, "items": attention, "generated_at": now})
}
func (s *Server) handleInboxRead(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "readonly")
	if !ok {
		return
	}
	var b struct {
		Read bool `json:"read"`
	}
	if !s.workflowBody(w, r, &b) {
		return
	}
	if len(r.PathValue("id")) > 300 {
		s.writeError(w, 400, "invalid item")
		return
	}
	id := sha256Hex(actor + "\x00" + s.keyScope(r) + "\x00" + r.PathValue("id"))
	var err error
	if b.Read {
		err = operations.Save(r.Context(), s.Store, "inbox_read", id, map[string]bool{"read": true})
	} else {
		err = s.Store.DeleteDocument(r.Context(), "inbox_read", id)
	}
	if err != nil {
		s.writeError(w, 500, "saving read state")
		return
	}
	s.writeJSON(w, 200, b)
}
func (s *Server) handleSearchAll(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len(q) < 2 || len(q) > 200 {
		s.writeError(w, 400, "search must be 2–200 characters")
		return
	}
	out := []attentionItem{}
	match := func(v string) bool { return strings.Contains(strings.ToLower(v), q) }
	hosts, err := s.scopedHosts(r)
	if err != nil {
		s.writeError(w, 500, "loading hosts")
		return
	}
	for _, h := range hosts {
		fs, e := s.Store.ListFacts(r.Context(), h.Name)
		if e != nil {
			s.writeError(w, 500, "loading facts")
			return
		}
		b, _ := json.Marshal(fs)
		if match(h.Name + " " + h.Platform + " " + h.Group + " " + string(b)) {
			out = append(out, attentionItem{ID: h.Name, Title: h.Name + " · " + h.Platform, Host: h.Name, Link: "#/host/" + h.Name})
		}
	}
	in, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, 500, "loading findings")
		return
	}
	queue, err := operations.Queue(r.Context(), s.Store, in, time.Now())
	if err != nil {
		s.writeError(w, 500, "loading findings")
		return
	}
	for _, v := range queue {
		if match(v.Title + " " + v.Evidence + " " + v.Host) {
			out = append(out, attentionItem{ID: v.ID, Title: v.Title, Host: v.Host, Link: "#/work"})
		}
	}
	for _, d := range docs.Index {
		b, _ := docs.Pages.ReadFile(d.Name + ".md")
		if match(d.Title + " " + string(b)) {
			out = append(out, attentionItem{ID: d.Name, Title: d.Title, Link: "#/docs/" + d.Name})
		}
	}
	if s.keyScope(r) == "" {
		assets, e := s.Store.ListDiscoveredAssets(r.Context())
		if e != nil {
			s.writeError(w, 500, "loading discoveries")
			return
		}
		for _, a := range assets {
			if match(a.Address) {
				out = append(out, attentionItem{ID: a.ID, Title: "Discovered address " + a.Address, Link: "#/visibility"})
			}
		}
		sites, e := operations.List[siteops.Sighting](r.Context(), s.Store, siteops.SightingKind)
		if e != nil {
			s.writeError(w, 500, "loading site discoveries")
			return
		}
		for _, a := range sites {
			if match(a.Address) {
				out = append(out, attentionItem{ID: a.ID, Title: "Site discovery " + a.Address, Link: "#/discovery"})
			}
		}
	}
	total := len(out)
	if total > 100 {
		out = out[:100]
	}
	s.writeJSON(w, 200, map[string]any{"items": out, "total": total})
}
func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	if !s.workflowHost(w, r, a) || !s.workflowHost(w, r, b) {
		return
	}
	left, err := s.Store.ListFacts(r.Context(), a)
	if err != nil {
		s.writeError(w, 500, "loading first device")
		return
	}
	right, err := s.Store.ListFacts(r.Context(), b)
	if err != nil {
		s.writeError(w, 500, "loading second device")
		return
	}
	flatten := func(fs []model.Fact) map[string]string {
		out := map[string]string{}
		for _, f := range fs {
			for k, v := range f.Data {
				b, _ := json.Marshal(v)
				out[f.Category+" / "+k] = string(b)
			}
		}
		return out
	}
	l, rr := flatten(left), flatten(right)
	keys := map[string]bool{}
	for k := range l {
		keys[k] = true
	}
	for k := range rr {
		keys[k] = true
	}
	names := []string{}
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	rows := []map[string]string{}
	for _, k := range names {
		if l[k] != rr[k] {
			rows = append(rows, map[string]string{"field": k, "left": l[k], "right": rr[k]})
		}
	}
	s.writeJSON(w, 200, map[string]any{"a": a, "b": b, "differences": rows, "note": "Current reported evidence; missing fields mean unknown, not absent. Collection timestamps may differ."})
}
func (s *Server) handleIntegrationHealth(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.unscopedAdmin(w, r); !ok {
		return
	}
	successes, e := operations.List[webhook.Success](r.Context(), s.Store, webhook.HealthKind)
	if e != nil {
		s.writeError(w, 500, "loading integration health")
		return
	}
	s.writeJSON(w, 200, map[string]any{"notifications": s.Webhooks.Snapshot(), "successes": successes, "siem_configured": s.SIEMForwarder != nil && s.SIEMForwarder.Configured(), "vulnerability_feed_configured": s.VulnFeed != nil, "note": "Configured does not establish reachability. Notification health retains the last successful delivery per destination from this release onward; pending/dead deliveries show failures. SIEM and feed status report configuration only."})
}
