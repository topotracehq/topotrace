/*******************************************************************************
 * @file         trust.go
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
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"muster/internal/breach"
	"muster/internal/signals"
	"muster/internal/trust"
	"muster/internal/ueba"
)

// handleTrust is GET /api/trust/{host}?min=N -- the device-trust
// verdict for an external gate (see internal/trust): score, level,
// allow (score >= min, default the "conditional" threshold), reasons.
// Readonly, so a gate can be given a readonly key scoped to nothing
// else. A denied decision is recorded to the audit trail so the
// operator can see which devices were turned away and why; allowed
// decisions are not, to keep the trail readable.
func (s *Server) handleTrust(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "readonly")
	if !ok {
		return
	}
	host, found, err := s.Store.GetHost(r.Context(), r.PathValue("host"))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	}
	if !found {
		// an unknown device is the most untrusted device there is --
		// answer with a verdict, not a 404, so a gate's logic is uniform
		s.writeJSON(w, http.StatusOK, map[string]any{
			"host": r.PathValue("host"), "score": 0, "level": "untrusted", "allow": false,
			"reasons": []string{"host is not enrolled in Muster"}, "evaluated_at": time.Now().UTC(),
		})
		return
	}
	minScore := 0
	if v := r.URL.Query().Get("min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			minScore = n
		}
	}
	rules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}
	in, err := signals.Gather(r.Context(), s.Store, host, rules, s.VulnFeed)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "gathering signals")
		return
	}
	v := trust.Evaluate(in, minScore, time.Now().UTC())
	if !v.Allow {
		if _, err := s.Store.RecordAudit(r.Context(), actor, "trust-denied", host.Name, "trust score "+strconv.Itoa(v.Score)+" below "+strconv.Itoa(v.MinScore)+": "+strings.Join(v.Reasons, "; ")); err != nil {
			s.log().Error("trust: recording audit entry", "err", err)
		}
	}
	s.writeJSON(w, http.StatusOK, v)
}

// handleSignals is GET /api/signals -- internal/ueba's behavioral
// findings over the audit trail. Admin, like the audit trail itself.
func (s *Server) handleSignals(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "admin"); !ok {
		return
	}
	entries, err := s.Store.ListAudit(r.Context(), "", 5000)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing audit trail")
		return
	}
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}
	sig := ueba.Analyze(entries, ueba.Options{Window: time.Duration(days) * 24 * time.Hour})
	if sig == nil {
		sig = []ueba.Signal{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"window_days":     days,
		"entries_scanned": len(entries),
		"signals":         sig,
		"note":            "Heuristic rules over Muster's own audit trail (off-hours writes, bursts, mass deletes, remediation runs, new admin keys, settings changes, first-seen actors) -- explainable, not a learned per-user baseline.",
	})
}

// handleBreaches is GET /api/breaches?domain=example.com -- with an HIBP
// API key, every alias on the domain seen in a breach; without one,
// the public list of breaches of that domain, and a clear note about
// which of the two it is. Admin: exposure data about named people.
func (s *Server) handleBreaches(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "admin")
	if !ok {
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if domain == "" || strings.ContainsAny(domain, "/ ") {
		s.writeError(w, http.StatusBadRequest, "domain is required, e.g. ?domain=example.com")
		return
	}
	client := s.Breach
	if client == nil {
		client = breach.New("")
	}
	out := map[string]any{"domain": domain, "account_lookup_configured": client.Configured()}
	if client.Configured() {
		aliases, err := client.BreachedDomain(r.Context(), domain)
		if err != nil && !errors.Is(err, breach.ErrNotConfigured) {
			s.writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		out["exposed_aliases"] = aliases
		out["exposed_count"] = len(aliases)
		out["mode"] = "accounts on this domain found in breaches (HIBP breacheddomain)"
	} else {
		out["mode"] = "public breaches OF this domain (HIBP breaches?domain=) -- account-level exposure needs -hibp-api-key"
	}
	public, err := client.Breaches(r.Context(), domain)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if public == nil {
		public = []breach.Breach{}
	}
	out["breaches_of_domain"] = public
	if _, err := s.Store.RecordAudit(r.Context(), actor, "breach-lookup", domain, "checked "+domain+" against Have I Been Pwned"); err != nil {
		s.log().Error("breach: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, out)
}
