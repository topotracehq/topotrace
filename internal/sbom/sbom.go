/*******************************************************************************
 * @file         sbom.go
 * @brief        Package sbom renders a host's installed_software fact as a CycloneDX 1.5 JSON software bill of materials, with the host's known vulnerability findings attached in CycloneDX's own vulnerabilities section -- so the inventory Muster already...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package sbom renders a host's installed_software fact as a CycloneDX
// 1.5 JSON software bill of materials, with the host's known
// vulnerability findings attached in CycloneDX's own vulnerabilities
// section -- so the inventory Muster already collects can be handed to
// anything that speaks the standard format (dependency-track, a
// customer's procurement process, an auditor) instead of only being
// browsable in Muster's UI.
//
// Scope, stated plainly: this is an OS-package-level SBOM (dpkg on
// Linux, the Uninstall registry on Windows), not an application
// dependency SBOM -- it says what's installed on the box, not what a
// binary was built from. purls follow the package-url spec's deb type
// for Debian/Ubuntu packages and the generic type otherwise.
package sbom

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"muster/internal/model"
	"muster/internal/vuln"
)

// Document is the CycloneDX 1.5 JSON shape (the subset Muster fills).
type Document struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
	Component Component `json:"component"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type    string `json:"type"` // "device" for the host, "application" for packages
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

type Vulnerability struct {
	ID          string    `json:"id"`
	Source      Source    `json:"source"`
	Ratings     []Rating  `json:"ratings"`
	Description string    `json:"description,omitempty"`
	Affects     []Affects `json:"affects"`
}

type Source struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type Rating struct {
	Severity string `json:"severity"`
}

type Affects struct {
	Ref string `json:"ref"`
}

// Build renders host's installed software (and findings) as a Document.
func Build(host model.Host, installed map[string]any, findings []vuln.Finding, now time.Time) Document {
	doc := Document{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		SerialNumber: fmt.Sprintf("urn:uuid:%s", pseudoUUID(host.Name, now)),
		Metadata: Metadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Tools:     []Tool{{Vendor: "Muster", Name: "muster", Version: "dev"}},
			Component: Component{Type: "device", BOMRef: "host:" + host.Name, Name: host.Name, Version: host.Platform},
		},
		Components: []Component{},
	}
	var list []map[string]any
	switch t := installed["items"].(type) {
	case []map[string]any:
		list = t
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				list = append(list, m)
			}
		}
	}
	refByName := map[string]string{}
	for _, m := range list {
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		version, _ := m["version"].(string)
		arch, _ := m["architecture"].(string)
		ref := "pkg:" + name + "@" + version
		c := Component{Type: "application", BOMRef: ref, Name: name, Version: version, Purl: purl(host.Platform, name, version, arch)}
		doc.Components = append(doc.Components, c)
		refByName[strings.ToLower(name)] = ref
	}
	for _, f := range findings {
		ref := refByName[strings.ToLower(f.Package)]
		if ref == "" {
			ref = "pkg:" + f.Package + "@" + f.Version
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, Vulnerability{
			ID:          f.CVE,
			Source:      Source{Name: "Muster vulnerability correlation", URL: "https://osv.dev/vulnerability/" + f.CVE},
			Ratings:     []Rating{{Severity: f.Severity}},
			Description: f.Description,
			Affects:     []Affects{{Ref: ref}},
		})
	}
	return doc
}

// JSON renders doc indented.
func JSON(doc Document) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}

func purl(platform, name, version, arch string) string {
	q := ""
	if arch != "" {
		q = "?arch=" + url.QueryEscape(arch)
	}
	switch platform {
	case "linux":
		return "pkg:deb/ubuntu/" + url.PathEscape(name) + "@" + url.PathEscape(version) + q
	default:
		return "pkg:generic/" + url.PathEscape(name) + "@" + url.PathEscape(version)
	}
}

// pseudoUUID is a deterministic UUID-shaped serial from host+time --
// CycloneDX wants a urn:uuid, and a stable-per-generation value is
// enough for a document that's regenerated on every request.
func pseudoUUID(host string, now time.Time) string {
	h := uint64(14695981039346656037)
	for _, b := range []byte(host + now.Format(time.RFC3339)) {
		h ^= uint64(b)
		h *= 1099511628211
	}
	x := fmt.Sprintf("%016x%016x", h, h*31)
	return x[0:8] + "-" + x[8:12] + "-4" + x[13:16] + "-a" + x[17:20] + "-" + x[20:32]
}
