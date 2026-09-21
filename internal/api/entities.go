/*******************************************************************************
 * @file         entities.go
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
	"strconv"
	"strings"

	"muster/internal/entitygraph"
)

// entitiesResponse is the entity map plus, when the request focused on
// one node, that node and its relationships -- so the dashboard's
// detail pane comes back with the graph instead of needing a second
// round trip. Embedding entitygraph.Graph keeps its fields at the top
// level of the JSON.
type entitiesResponse struct {
	entitygraph.Graph
	Node      *entitygraph.Node      `json:"node,omitempty"`
	Relations []entitygraph.Relation `json:"relations,omitempty"`
}

// handleEntities is GET /api/entities -- the fleet's entity
// relationship map (see internal/entitygraph).
//
// Query parameters, all optional:
//
//	types=host,cve,...  keep only these entity kinds (default: all)
//	focus=<node id>     keep only nodes within depth hops of this one
//	depth=N             how far focus reaches (default 1, capped at 4)
//	max=N               node cap (default entitygraph.DefaultMaxNodes)
//
// Group-scoped like every other fleet view: a group-scoped API key
// sees only its own hosts, and therefore only the entities those hosts
// reach.
func (s *Server) handleEntities(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	inputs, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "gathering fleet signals")
		return
	}
	rules, err := s.Store.ListRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing rules")
		return
	}
	softwareRules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}

	opts := entitygraph.Options{Focus: strings.TrimSpace(r.URL.Query().Get("focus"))}
	if raw := r.URL.Query().Get("types"); strings.TrimSpace(raw) != "" {
		valid := map[string]bool{}
		for _, k := range entitygraph.Kinds {
			valid[k] = true
		}
		opts.Types = map[string]bool{}
		for _, t := range strings.Split(raw, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if valid[t] {
				opts.Types[t] = true
			}
		}
		// An all-invalid types list would otherwise read as "no filter"
		// and quietly return the whole graph, which is the opposite of
		// what the caller asked for.
		if len(opts.Types) == 0 {
			s.writeError(w, http.StatusBadRequest, "types must name at least one of: "+strings.Join(entitygraph.Kinds, ", "))
			return
		}
	}
	if d, err := strconv.Atoi(r.URL.Query().Get("depth")); err == nil && d > 0 {
		if d > 4 {
			d = 4 // past four hops a focused view is the whole graph again
		}
		opts.Depth = d
	}
	if m, err := strconv.Atoi(r.URL.Query().Get("max")); err == nil && m > 0 {
		opts.MaxNodes = m
	}

	g := entitygraph.Build(inputs, rules, softwareRules, opts)
	resp := entitiesResponse{Graph: g}
	if g.Focus != "" {
		for i := range g.Nodes {
			if g.Nodes[i].ID == g.Focus {
				resp.Node = &g.Nodes[i]
				break
			}
		}
		resp.Relations = g.Neighbors(g.Focus)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleEntityKinds is GET /api/entities/kinds -- the legend's own
// vocabulary (entity kinds, the family each belongs to, and the
// relationship types), served from the binary so the dashboard's
// legend and filter row can never drift from what Build actually
// produces.
func (s *Server) handleEntityKinds(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	kinds := make([]map[string]string, 0, len(entitygraph.Kinds))
	for _, k := range entitygraph.Kinds {
		kinds = append(kinds, map[string]string{"kind": k, "family": entitygraph.Families[k]})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"kinds":      kinds,
		"edge_kinds": entitygraph.EdgeKinds,
		"max_nodes":  entitygraph.DefaultMaxNodes,
	})
}
