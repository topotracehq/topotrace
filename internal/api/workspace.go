/*******************************************************************************
 * @file         workspace.go
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
	"runtime/debug"
	"strings"
	"time"

	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/webhook"
)

const savedViewKind = "saved_view"
const releaseVersion = "2026.09.18.6"

type savedView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	Shared bool   `json:"shared"`
	Page   string `json:"page"`
	Query  string `json:"query"`
	Filter string `json:"filter"`
	Layout string `json:"layout"`
}

func (v savedView) validate() error {
	if len(strings.TrimSpace(v.Name)) == 0 || len(v.Name) > 100 || len(v.Query) > 200 {
		return fmt.Errorf("provide a name up to 100 characters and a search up to 200 characters")
	}
	if v.Page != "history" && v.Page != "health" && v.Page != "discovery" && v.Page != "work" {
		return fmt.Errorf("unknown view")
	}
	if v.Layout != "comfortable" && v.Layout != "compact" {
		return fmt.Errorf("unknown layout")
	}
	if len(v.Filter) > 100 {
		return fmt.Errorf("filter too long")
	}
	return nil
}
func (s *Server) registerWorkspace(mux *http.ServeMux) {
	s.registerProductivity(mux)
	s.registerSiteOps(mux)
	mux.HandleFunc("GET /api/about", s.handleAbout)
	mux.HandleFunc("GET /api/saved-views", s.handleSavedViews)
	mux.HandleFunc("POST /api/saved-views", s.handleSavedViews)
	mux.HandleFunc("DELETE /api/saved-views/{id}", s.handleDeleteView)
	mux.HandleFunc("GET /api/notification-preferences", s.handleNotificationPreferences)
	mux.HandleFunc("PUT /api/notification-preferences", s.handleNotificationPreferences)
	mux.HandleFunc("GET /api/config-backup", s.handleConfigBackup)
	mux.HandleFunc("POST /api/config-backup/preview", s.handleConfigRestore)
	mux.HandleFunc("POST /api/config-backup/restore", s.handleConfigRestore)
	mux.HandleFunc("POST /api/change-plans/preflight", s.handlePreflight)
}
func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	revision := "source build"
	if b, ok := debug.ReadBuildInfo(); ok {
		for _, v := range b.Settings {
			if v.Key == "vcs.revision" {
				revision = v.Value
			}
			if v.Key == "vcs.modified" && v.Value == "true" {
				revision += " (modified)"
			}
		}
	}
	s.writeJSON(w, 200, map[string]any{"product": "TopoTrace", "version": releaseVersion, "revision": revision, "company": "TopoTrace LLC", "copyright": "© 2026 TopoTrace LLC.", "support": "Contact the administrator who manages your TopoTrace deployment. Include this version and a description of the issue; do not include passwords or API tokens."})
}
func (s *Server) handleSavedViews(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "readonly")
	if !ok {
		return
	}
	group := s.keyScope(r)
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	if r.Method == "POST" {
		var v savedView
		if !s.workflowBody(w, r, &v) {
			return
		}
		if err := v.validate(); err != nil {
			s.writeError(w, 400, err.Error())
			return
		}
		if v.Shared {
			if _, ok := s.requireRoleStrict(w, r, "remediate"); !ok {
				return
			}
		}
		v.ID = operations.ID()
		v.Owner = actor
		v.Group = group
		docs, err := s.Store.ListDocuments(r.Context(), savedViewKind)
		if err != nil {
			s.writeError(w, 500, "loading views")
			return
		}
		count := 0
		for _, d := range docs {
			var old savedView
			if json.Unmarshal(d.Data, &old) == nil && old.Owner == actor && old.Group == group {
				count++
			}
		}
		if count >= 50 {
			s.writeError(w, 400, "delete an old view before adding more (limit 50 per account and group)")
			return
		}
		if err := operations.Save(r.Context(), s.Store, savedViewKind, v.ID, v); err != nil {
			s.writeError(w, 500, "saving view")
			return
		}
		s.writeJSON(w, 201, v)
		return
	}
	views, err := operations.List[savedView](r.Context(), s.Store, savedViewKind)
	if err != nil {
		s.writeError(w, 500, "loading views")
		return
	}
	out := []savedView{}
	for _, v := range views {
		if v.Group == group && (v.Shared || v.Owner == actor) {
			out = append(out, v)
		}
	}
	s.writeJSON(w, 200, out)
}
func (s *Server) handleDeleteView(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "readonly")
	if !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	v, found, err := operations.Load[savedView](r.Context(), s.Store, savedViewKind, r.PathValue("id"))
	if err != nil {
		s.writeError(w, 500, "loading view")
		return
	}
	if !found || v.Owner != actor || v.Group != s.keyScope(r) {
		s.writeError(w, 404, "view not found or not owned by you")
		return
	}
	if err := s.Store.DeleteDocument(r.Context(), savedViewKind, v.ID); err != nil {
		s.writeError(w, 500, "deleting view")
		return
	}
	w.WriteHeader(204)
}
func (s *Server) unscopedAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return "", false
	}
	if s.keyScope(r) != "" {
		s.writeError(w, 403, "requires an unscoped administrator")
		return "", false
	}
	return actor, true
}
func (s *Server) handleNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.unscopedAdmin(w, r)
	if !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	if r.Method == "PUT" {
		var p webhook.Preferences
		if !s.workflowBody(w, r, &p) {
			return
		}
		if err := p.Validate(); err != nil {
			s.writeError(w, 400, err.Error())
			return
		}
		if err := operations.Save(r.Context(), s.Store, webhook.PreferencesKind, "global", p); err != nil {
			s.writeError(w, 500, "saving notification preferences")
			return
		}
		s.Store.RecordAudit(r.Context(), actor, "notification-preferences", "global", "Updated quiet hours, digest, and escalation preferences")
	}
	p, err := webhook.LoadPreferences(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, 500, "loading preferences")
		return
	}
	s.writeJSON(w, 200, p)
}

type configBackup struct {
	Format    string           `json:"format"`
	CreatedAt time.Time        `json:"created_at"`
	Documents []model.Document `json:"documents"`
}

var backupKinds = []string{operations.GroupKind, savedViewKind, webhook.PreferencesKind}

func validateBackup(b configBackup) error {
	if b.Format != "muster-workspace-config-v1" || len(b.Documents) > 1000 {
		return fmt.Errorf("unsupported format or too many records")
	}
	seen := map[string]bool{}
	for _, d := range b.Documents {
		key := d.Kind + "/" + d.ID
		if seen[key] || d.ID == "" || len(d.ID) > 200 {
			return fmt.Errorf("duplicate or invalid record ID")
		}
		seen[key] = true
		switch d.Kind {
		case operations.GroupKind:
			var g operations.DynamicGroup
			if json.Unmarshal(d.Data, &g) != nil || g.ID != d.ID || strings.TrimSpace(g.Name) == "" || len(g.Name) > 200 || g.Selector.MinRisk < 0 || g.Selector.MinRisk > 100 {
				return fmt.Errorf("invalid dynamic group")
			}
		case savedViewKind:
			var v savedView
			if json.Unmarshal(d.Data, &v) != nil || v.ID != d.ID || v.Owner == "" || v.validate() != nil {
				return fmt.Errorf("invalid saved view")
			}
		case webhook.PreferencesKind:
			var p webhook.Preferences
			if d.ID != "global" || json.Unmarshal(d.Data, &p) != nil || p.Validate() != nil {
				return fmt.Errorf("invalid notification preferences")
			}
		default:
			return fmt.Errorf("record type %q cannot be restored; only groups, views, and notification preferences are supported", d.Kind)
		}
	}
	return nil
}
func (s *Server) handleConfigBackup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.unscopedAdmin(w, r); !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	b := configBackup{Format: "muster-workspace-config-v1", CreatedAt: time.Now().UTC(), Documents: []model.Document{}}
	for _, kind := range backupKinds {
		docs, err := s.Store.ListDocuments(r.Context(), kind)
		if err != nil {
			s.writeError(w, 500, "exporting configuration")
			return
		}
		b.Documents = append(b.Documents, docs...)
	}
	w.Header().Set("Cache-Control", "no-store")
	raw, _ := json.Marshal(b)
	if len(b.Documents) > 1000 || len(raw) > 3<<20 {
		s.writeError(w, 413, "configuration exceeds portable backup limits; use full-server backup procedure")
		return
	}
	s.writeJSON(w, 200, b)
}

// Restore is deliberately additive: existing records are never overwritten or
// deleted. A failed or interrupted import can be resumed with the same file.
func (s *Server) handleConfigRestore(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.unscopedAdmin(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var req struct {
		Backup      configBackup `json:"backup"`
		PreviewHash string       `json:"preview_hash"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil {
		s.writeError(w, 400, "invalid backup (maximum 4 MB)")
		return
	}
	if err := validateBackup(req.Backup); err != nil {
		s.writeError(w, 400, err.Error())
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	creates := []model.Document{}
	skipped := []string{}
	fingerprint := []any{req.Backup}
	for _, d := range req.Backup.Documents {
		old, exists, err := s.Store.GetDocument(r.Context(), d.Kind, d.ID)
		if err != nil {
			s.writeError(w, 500, "checking existing configuration")
			return
		}
		fingerprint = append(fingerprint, old, exists)
		if exists {
			skipped = append(skipped, d.Kind+"/"+d.ID)
		} else {
			creates = append(creates, d)
		}
	}
	raw, _ := json.Marshal(fingerprint)
	hash := sha256Hex(string(raw))
	if strings.HasSuffix(r.URL.Path, "/restore") {
		if req.PreviewHash != hash {
			s.writeError(w, 409, "configuration changed or preview missing; preview this file again")
			return
		}
		applied := 0
		for _, d := range creates {
			if err := s.Store.PutDocument(r.Context(), d); err != nil {
				s.writeError(w, 500, fmt.Sprintf("restore stopped after %d records; existing records preserved; preview and retry the same file to resume", applied))
				return
			}
			applied++
		}
		s.Store.RecordAudit(r.Context(), actor, "config-restored", "workspace", fmt.Sprintf("Created %d missing configuration records; skipped %d existing records", applied, len(skipped)))
	}
	names := []string{}
	for _, d := range creates {
		names = append(names, d.Kind+"/"+d.ID)
	}
	s.writeJSON(w, 200, map[string]any{"preview_hash": hash, "create": names, "skip_existing": skipped, "note": "Merge-only recovery: existing records are preserved. Includes dynamic groups, saved views, and notification preferences. Excludes inventory, policies, credentials, integrations, actions, exceptions, and server settings."})
}
