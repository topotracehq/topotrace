/*******************************************************************************
 * @file         risk.go
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

	"topotrace/internal/benchmark"
	"topotrace/internal/compliance"
	"topotrace/internal/history"
	"topotrace/internal/risk"
	"topotrace/internal/signals"
)

// fleetInputs gathers a compliance.Input for every host -- the shared
// first step of every fleet-wide rollup (risk, benchmark, reports).
// Hosts whose facts can't be loaded are logged and skipped, never fatal.
func (s *Server) fleetInputs(r *http.Request) ([]compliance.Input, error) {
	hosts, err := s.scopedHosts(r)
	if err != nil {
		return nil, err
	}
	softwareRules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		return nil, err
	}
	out := make([]compliance.Input, 0, len(hosts))
	for _, h := range hosts {
		in, err := signals.Gather(r.Context(), s.Store, h, softwareRules, s.VulnFeed)
		if err != nil {
			s.log().Error("gathering signals", "host", h.Name, "err", err)
			continue
		}
		out = append(out, in)
	}
	return out, nil
}

// handleFleetRisk is GET /api/risk -- every host's blended risk score
// (see internal/risk), riskiest first, plus a level distribution.
func (s *Server) handleFleetRisk(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	inputs, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "gathering fleet signals")
		return
	}
	results := make([]risk.Result, 0, len(inputs))
	dist := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	sum := 0
	for _, in := range inputs {
		res := risk.Compute(in)
		results = append(results, res)
		dist[res.Level]++
		sum += res.Score
	}
	risk.Rank(results)
	avg := 0
	if len(results) > 0 {
		avg = sum / len(results)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"total_hosts":   len(results),
		"average_score": avg,
		"by_level":      dist,
		"hosts":         results,
	})
}

// handleHostRisk is GET /api/hosts/{host}/risk -- one host's score with
// its factor breakdown.
func (s *Server) handleHostRisk(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	host, ok, err := s.Store.GetHost(r.Context(), r.PathValue("host"))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}
	softwareRules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}
	in, err := signals.Gather(r.Context(), s.Store, host, softwareRules, s.VulnFeed)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "gathering signals")
		return
	}
	s.writeJSON(w, http.StatusOK, risk.Compute(in))
}

// handleBenchmark is GET /api/benchmark -- the fleet's headline numbers
// against internal/benchmark's illustrative reference baseline. The
// response says in so many words that the baseline is illustrative.
func (s *Server) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	inputs, err := s.fleetInputs(r)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "gathering fleet signals")
		return
	}
	f := benchmark.Fleet{}
	if n := float64(len(inputs)); n > 0 {
		var posture, comp, vulns, stale, shadow float64
		for _, in := range inputs {
			posture += float64(in.Posture.Score)
			comp += float64(compliance.Baseline.Evaluate(in).Score)
			if len(in.VulnFindings) > 0 {
				vulns++
			}
			if in.Stale {
				stale++
			}
			if len(in.ShadowAIViolations) > 0 {
				shadow++
			}
		}
		f.AvgPosture, f.AvgCompliance = posture/n, comp/n
		f.PctWithVulns, f.PctStale, f.PctShadowAI = vulns/n*100, stale/n*100, shadow/n*100
	}
	if all, err := history.All(r.Context(), s.Store); err == nil {
		if m := history.TimeToRemediate(all, time.Now().UTC(), 90*24*time.Hour); m.Resolved > 0 {
			f.MTTRHours, f.MTTRMeasured = m.MeanHours, true
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"baseline":    benchmark.Name,
		"total_hosts": len(inputs),
		"metrics":     benchmark.Compare(f),
	})
}
