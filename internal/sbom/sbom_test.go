/*******************************************************************************
 * @file         sbom_test.go
 * @brief        Tests for the Muster sbom package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"muster/internal/model"
	"muster/internal/vuln"
)

func TestBuild(t *testing.T) {
	installed := map[string]any{"count": 2, "items": []any{
		map[string]any{"name": "bash", "version": "4.3-7", "architecture": "amd64"},
		map[string]any{"name": "curl", "version": "8.5.0"},
	}}
	findings := []vuln.Finding{{Package: "bash", Version: "4.3-7", CVE: "CVE-2014-6271", Severity: "critical", Description: "Shellshock"}}
	doc := Build(model.Host{Name: "web01", Platform: "linux"}, installed, findings, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || len(doc.Components) != 2 || len(doc.Vulnerabilities) != 1 {
		t.Fatalf("%+v", doc)
	}
	if doc.Components[0].Purl != "pkg:deb/ubuntu/bash@4.3-7?arch=amd64" {
		t.Fatalf("purl: %s", doc.Components[0].Purl)
	}
	if doc.Vulnerabilities[0].Affects[0].Ref != "pkg:bash@4.3-7" {
		t.Fatalf("affects: %+v", doc.Vulnerabilities[0])
	}
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") || len(doc.SerialNumber) != len("urn:uuid:")+36 {
		t.Fatalf("serial: %s", doc.SerialNumber)
	}
	out, err := JSON(doc)
	if err != nil || !json.Valid(out) {
		t.Fatalf("json: %v", err)
	}
	win := Build(model.Host{Name: "w", Platform: "windows"}, map[string]any{"items": []map[string]any{{"name": "Docker Desktop", "version": "4.29.0"}}}, nil, time.Now())
	if win.Components[0].Purl != "pkg:generic/Docker%20Desktop@4.29.0" {
		t.Fatalf("windows purl: %s", win.Components[0].Purl)
	}
}
