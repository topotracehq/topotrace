/*******************************************************************************
 * @file         agenthealth.go
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
	"net/http"
	"time"

	"muster/internal/agenthealth"
)

// handleAgentHealth is GET /api/agents/health -- every host's agent
// status (see internal/agenthealth): last check-in, cadence, late/
// missing/failing verdict, failure count. Worst first, plus counts.
func (s *Server) handleAgentHealth(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	now := time.Now().UTC()
	all, err := agenthealth.All(r.Context(), s.Store, now)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "loading agent health")
		return
	}
	// hosts that exist but have never had an agent-health record (seeded
	// data, or a host from before this bookkeeping existed) are listed
	// as "never" so the Agents tab shows the whole fleet, not just the
	// hosts that have reported since the feature landed
	seen := map[string]bool{}
	for _, st := range all {
		seen[st.Host] = true
	}
	if hosts, err := s.Store.ListHosts(r.Context()); err == nil {
		for _, h := range hosts {
			if !seen[h.Name] {
				st := agenthealth.Evaluate(agenthealth.Record{Host: h.Name}, now)
				if !h.LastCooked.IsZero() {
					st.LastCheckin = h.LastCooked
					if now.Sub(h.LastCooked) > 24*time.Hour {
						st.State, st.Detail = "missing", "last report predates agent-health tracking and is past the 24h window"
					} else {
						st.State, st.Detail = "healthy", "reported "+humanAgoAPI(now.Sub(h.LastCooked))+" ago (before agent-health tracking; cadence unknown)"
					}
				}
				all = append(all, st)
			}
		}
	}
	counts := map[string]int{}
	for _, st := range all {
		counts[st.State]++
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"counts": counts, "agents": all})
}

func humanAgoAPI(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return d.Truncate(time.Minute).String()
	default:
		return d.Truncate(time.Hour).String()
	}
}
