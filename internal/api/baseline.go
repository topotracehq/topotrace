/*******************************************************************************
 * @file         baseline.go
 * @brief        Part of the Muster api module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"muster/internal/baseline"
	"muster/internal/store"
)

// handleGetBaseline is GET /api/hosts/{host}/baseline -- the host's
// golden baseline compared against its facts right now (see
// internal/baseline). A host with no baseline answers has_baseline
// false, not 404, so the UI can offer to capture one.
func (s *Server) handleGetBaseline(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	if _, ok, err := s.Store.GetHost(r.Context(), name); err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	} else if !ok {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}
	rep, err := baseline.Compare(r.Context(), s.Store, name)
	if err != nil {
		s.log().Error("baseline: comparing", "host", name, "err", err)
		s.writeError(w, http.StatusInternalServerError, "comparing baseline")
		return
	}
	s.writeJSON(w, http.StatusOK, rep)
}

// handleCaptureBaseline is POST /api/hosts/{host}/baseline -- captures
// the host's current facts as its baseline (replacing any existing
// one). Body: {"note": "...", "categories": [...]} both optional.
// Gated admin and strictly: declaring a state "known good" is an
// operator decision that should be attributable.
func (s *Server) handleCaptureBaseline(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	name := r.PathValue("host")
	var req struct {
		Note       string   `json:"note"`
		Categories []string `json:"categories"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // an empty body is fine
	}
	b, err := baseline.Capture(r.Context(), s.Store, name, actor, req.Note, req.Categories)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "baseline-captured", name, "captured "+strconv.Itoa(len(b.Facts))+" categories as golden baseline"); err != nil {
		s.log().Error("baseline: recording audit entry", "err", err)
	}
	rep, err := baseline.Compare(r.Context(), s.Store, name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "comparing baseline")
		return
	}
	s.writeJSON(w, http.StatusCreated, rep)
}

// handleDeleteBaseline is DELETE /api/hosts/{host}/baseline.
func (s *Server) handleDeleteBaseline(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	name := r.PathValue("host")
	if err := baseline.Delete(r.Context(), s.Store, name); err != nil {
		if errors.Is(err, store.ErrDocumentNotFound) {
			s.writeError(w, http.StatusNotFound, "no baseline for this host")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "deleting baseline")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "baseline-cleared", name, "golden baseline removed"); err != nil {
		s.log().Error("baseline: recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleFleetDrift is GET /api/drift -- every baselined host's drift
// report, drifted hosts first.
func (s *Server) handleFleetDrift(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	all, err := baseline.All(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "comparing baselines")
		return
	}
	drifted := 0
	for _, rep := range all {
		if rep.Drifted {
			drifted++
		}
	}
	// drifted first, then by host
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if (!all[i].Drifted && all[j].Drifted) || (all[i].Drifted == all[j].Drifted && all[i].Host > all[j].Host) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"baselined": len(all),
		"drifted":   drifted,
		"hosts":     all,
	})
}
