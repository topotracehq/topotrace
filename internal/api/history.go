/*******************************************************************************
 * @file         history.go
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
	"time"

	"muster/internal/history"
)

// historyWindow parses ?days= (default 30, capped at 365) into a window.
func historyWindow(r *http.Request) time.Duration {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	return time.Duration(days) * 24 * time.Hour
}

// handleFleetHistory is GET /api/history?days=N -- the fleet-wide
// score trend (one bucket per day, or per hour when days <= 2) plus
// the time-to-remediate rollup over the same window. Everything here
// comes from internal/history's per-host series, recorded by the
// background evaluator once per run; a brand-new server has no history
// yet and answers with empty buckets rather than an error.
func (s *Server) handleFleetHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	all, err := history.All(r.Context(), s.Store)
	if err != nil {
		s.log().Error("history: loading series", "err", err)
		s.writeError(w, http.StatusInternalServerError, "loading score history")
		return
	}
	window := historyWindow(r)
	step := 24 * time.Hour
	if window <= 48*time.Hour {
		step = time.Hour
	}
	now := time.Now().UTC()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"window_days":   int(window.Hours() / 24),
		"step":          step.String(),
		"hosts_tracked": len(all),
		"buckets":       history.FleetRollup(all, now, window, step),
		"mttr":          history.TimeToRemediate(all, now, window),
	})
}

// handleHostHistory is GET /api/hosts/{host}/history?days=N -- one
// host's raw recorded points inside the window, oldest first.
func (s *Server) handleHostHistory(w http.ResponseWriter, r *http.Request) {
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
	series, err := history.Get(r.Context(), s.Store, name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "loading score history")
		return
	}
	cutoff := time.Now().UTC().Add(-historyWindow(r))
	points := make([]history.Point, 0, len(series.Points))
	for _, p := range series.Points {
		if !p.At.Before(cutoff) {
			points = append(points, p)
		}
	}
	s.writeJSON(w, http.StatusOK, history.Series{Host: name, Points: points})
}
