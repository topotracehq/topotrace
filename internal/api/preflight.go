/*******************************************************************************
 * @file         preflight.go
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
	"net/http"
	"time"
	"topotrace/internal/operations"
)

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoleStrict(w, r, "remediate"); !ok {
		return
	}
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
	p.ID = ""
	p.Actions = nil
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	check, err := operations.Preflight(r.Context(), s.Store, p, time.Now().UTC())
	if err != nil {
		s.writeError(w, 500, "checking change impact")
		return
	}
	s.writeJSON(w, 200, check)
}
