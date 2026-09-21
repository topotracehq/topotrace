/*******************************************************************************
 * @file         scanner.go
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
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"topotrace/internal/graph"
	"topotrace/internal/model"
	"topotrace/internal/scanner"
)

// scannerImportResult is what POST /api/scanner-import returns.
type scannerImportResult struct {
	Format    string                       `json:"format"`
	Parsed    int                          `json:"parsed"`
	Matched   map[string]int               `json:"matched"`   // topotrace host -> findings stored
	Unmatched map[string][]scanner.Finding `json:"unmatched"` // scanner host name -> findings (not stored)
	Hosts     []string                     `json:"hosts"`     // matched hosts, alphabetical
}

// handleScannerImport is POST /api/scanner-import?format=nessus|qualys|generic.
// The body is the scanner's CSV export. Findings are matched to TopoTrace
// hosts by hostname, short hostname, or an IPv4 address from the host's
// network_interfaces fact, then stored as a scanner_findings fact per
// host so they flow into compliance, risk and the summary alongside
// TopoTrace's own version matching. Hosts the scanner named that TopoTrace
// does not know come back as unmatched and are not stored. Admin only.
// A 2 MB body limit keeps a stray full-fleet export from being a
// memory problem; split larger exports.
func (s *Server) handleScannerImport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "generic"
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		s.writeError(w, http.StatusRequestEntityTooLarge, "scanner export too large (2 MB limit); split it")
		return
	}
	findings, err := scanner.Parse(format, strings.NewReader(string(body)))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hosts, err := s.scopedHosts(r)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing hosts")
		return
	}
	addrs := map[string][]string{}
	for _, h := range hosts {
		f, ok, err := s.Store.GetFact(r.Context(), h.Name, "network_interfaces")
		addrs[h.Name] = graph.HostAddresses(f, ok && err == nil)
	}
	matched, unmatched := scanner.Match(findings, addrs)

	now := time.Now().UTC()
	res := scannerImportResult{Format: format, Parsed: len(findings), Matched: map[string]int{}, Unmatched: unmatched}
	for host, list := range matched {
		if _, err := s.Store.UpsertFact(r.Context(), model.Fact{
			Host: host, Category: "scanner_findings", Data: scanner.ToFact(format, list), CookedAt: now,
		}); err != nil {
			s.log().Error("scanner import: storing findings", "host", host, "err", err)
			continue
		}
		res.Matched[host] = len(list)
		res.Hosts = append(res.Hosts, host)
	}
	sort.Strings(res.Hosts)
	if _, err := s.Store.RecordAudit(r.Context(), actor, "scanner-import", format,
		"imported "+strconv.Itoa(len(findings))+" findings for "+strconv.Itoa(len(res.Hosts))+" hosts ("+strconv.Itoa(len(unmatched))+" unmatched scanner hosts)"); err != nil {
		s.log().Error("scanner import: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, res)
}

// handleScannerFormats is GET /api/scanner-import/formats.
func (s *Server) handleScannerFormats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"formats": scanner.Formats})
}
