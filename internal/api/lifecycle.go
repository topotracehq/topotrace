/*******************************************************************************
 * @file         lifecycle.go
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
	"time"

	"muster/internal/certs"
	"muster/internal/eol"
	"muster/internal/sbom"
	"muster/internal/signals"
	"muster/internal/sprawl"
	"muster/internal/vuln"
)

// handleHostSBOM is GET /api/hosts/{host}/sbom -- a CycloneDX 1.5 JSON
// bill of materials for the host's installed software, with its known
// vulnerability findings attached. Served as a download.
func (s *Server) handleHostSBOM(w http.ResponseWriter, r *http.Request) {
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
	installed, _, err := s.Store.GetFact(r.Context(), host.Name, "installed_software")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching installed software")
		return
	}
	var findings []vuln.Finding
	if installed.Data != nil {
		findings = vuln.CheckWithFeed(installed.Data["items"], s.VulnFeed)
	}
	doc := sbom.Build(host, installed.Data, findings, time.Now().UTC())
	out, err := sbom.JSON(doc)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "rendering sbom")
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.5")
	w.Header().Set("Content-Disposition", `attachment; filename="`+host.Name+`.cdx.json"`)
	w.Write(out)
}

// handleHostLifecycle is GET /api/hosts/{host}/lifecycle -- the host's
// OS end-of-life status and every server certificate with its expiry
// verdict, the two "it worked yesterday" findings.
func (s *Server) handleHostLifecycle(w http.ResponseWriter, r *http.Request) {
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
	byCat, err := signals.FactsByCategory(r.Context(), s.Store, name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching facts")
		return
	}
	now := time.Now().UTC()
	osStatus := eol.Status{State: "unknown", Detail: "no system_summary reported"}
	if sum, ok := byCat["system_summary"]; ok {
		osStatus = eol.Check(sum.Data, now)
	}
	certList := []certs.Cert{}
	reported := false
	if tc, ok := byCat["tls_certificates"]; ok {
		reported = true
		certList = certs.FromFact(tc.Data["items"], now)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"host":               name,
		"os":                 osStatus,
		"certificates":       certList,
		"certs_reported":     reported,
		"certificate_issues": len(certs.Problems(certList)),
	})
}

// handleSprawl is GET /api/software/sprawl -- the fleet's installed
// software rolled up against internal/sprawl's commercial/SaaS catalog:
// seats per product, licensed seats, and categories with more than one
// product doing the same job.
func (s *Server) handleSprawl(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	hosts, err := s.Store.ListHosts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing hosts")
		return
	}
	fleet := sprawl.HostSoftware{}
	for _, h := range hosts {
		fact, ok, err := s.Store.GetFact(r.Context(), h.Name, "installed_software")
		if err != nil || !ok {
			fleet[h.Name] = nil
			continue
		}
		var names []string
		switch t := fact.Data["items"].(type) {
		case []map[string]any:
			for _, m := range t {
				if n, _ := m["name"].(string); n != "" {
					names = append(names, n)
				}
			}
		case []any:
			for _, x := range t {
				if m, ok := x.(map[string]any); ok {
					if n, _ := m["name"].(string); n != "" {
						names = append(names, n)
					}
				}
			}
		}
		fleet[h.Name] = names
	}
	s.writeJSON(w, http.StatusOK, sprawl.Rollup(fleet))
}
