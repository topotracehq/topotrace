/*******************************************************************************
 * @file         aiagentinv.go
 * @brief        Part of the TopoTrace api module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"net/http"

	"topotrace/internal/aiagentinv"
)

// handleHostAIAgents is GET /api/hosts/{host}/ai-agents -- every AI
// CLI/IDE-agent tool, MCP server config, and provider-API-key presence
// record the host's agent found, evaluated by internal/aiagentinv,
// riskiest first, plus a risky count. A host whose agent hasn't
// reported the ai_agent_inventory category (older agent, non-Linux, or
// nothing found) gets an empty list, not an error. Community-edition
// visibility only -- see docs/ai-agent-inventory.md.
func (s *Server) handleHostAIAgents(w http.ResponseWriter, r *http.Request) {
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
	fact, ok, err := s.Store.GetFact(r.Context(), name, "ai_agent_inventory")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching ai agent inventory")
		return
	}
	findings := []aiagentinv.Finding{}
	if ok {
		tools, servers, keys := aiagentinv.FromFact(fact.Data)
		findings = aiagentinv.Evaluate(tools, servers, keys)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"host":     name,
		"reported": ok,
		"total":    len(findings),
		"risky":    len(aiagentinv.Risky(findings)),
		"findings": findings,
	})
}
