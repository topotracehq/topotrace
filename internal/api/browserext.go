/*******************************************************************************
 * @file         browserext.go
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
	"net/http"

	"muster/internal/browserext"
)

// handleHostBrowserExtensions is GET /api/hosts/{host}/browser-extensions
// -- every extension the host's agent found, evaluated by
// internal/browserext, riskiest first, plus a risky count. A host whose
// agent hasn't reported the browser_extensions category (older agent,
// or simply no browser installed) gets an empty list, not an error.
func (s *Server) handleHostBrowserExtensions(w http.ResponseWriter, r *http.Request) {
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
	fact, ok, err := s.Store.GetFact(r.Context(), name, "browser_extensions")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching browser extensions")
		return
	}
	findings := []browserext.Finding{}
	if ok {
		findings = browserext.Evaluate(browserext.FromFact(fact.Data["items"]))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"host":       name,
		"reported":   ok,
		"total":      len(findings),
		"risky":      len(browserext.Risky(findings)),
		"extensions": findings,
	})
}
