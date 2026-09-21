/*******************************************************************************
 * @file         scanner.go
 * @brief        Package scanner imports findings from a vulnerability scanner an organization already runs -- Tenable Nessus and Qualys CSV exports, plus a small generic CSV -- and attaches them to Muster's hosts, so the "we already have a scanner" conv...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package scanner imports findings from a vulnerability scanner an
// organization already runs -- Tenable Nessus and Qualys CSV exports,
// plus a small generic CSV -- and attaches them to Muster's hosts, so
// the "we already have a scanner" conversation ends with "good, feed it
// in" rather than a second, competing list. Imported findings live in
// a scanner_findings fact per host (so they get change tracking like
// any other fact) and are merged into the same vulnerability list
// Muster's own OSV/static correlation produces, tagged with their
// source, so compliance, risk, reports and the SBOM see one set.
//
// Column names follow each vendor's default CSV export as documented;
// an export with renamed or missing columns imports what it can and
// reports which rows it couldn't place. Neither format has been
// checked against a live scanner export from this environment -- only
// against hand-written samples shaped like the documented ones.
package scanner

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"muster/internal/vuln"
)

// Finding is one imported scanner result.
type Finding struct {
	Host        string  `json:"host"`     // as the scanner named it (hostname, FQDN or IP)
	CVE         string  `json:"cve"`      // may be "" for a plugin with no CVE
	Severity    string  `json:"severity"` // normalized: critical/high/medium/low/info
	Title       string  `json:"title"`    // plugin/QID title
	Port        string  `json:"port,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	PluginID    string  `json:"plugin_id,omitempty"`
	Source      string  `json:"source"` // "nessus", "qualys", "generic"
	Description string  `json:"description,omitempty"`
}

// Formats lists what Parse accepts.
var Formats = []string{"nessus", "qualys", "generic"}

// Parse reads a CSV export in the named format.
func Parse(format string, r io.Reader) ([]Finding, error) {
	rd := csv.NewReader(r)
	rd.LazyQuotes = true
	rd.FieldsPerRecord = -1
	records, err := rd.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("scanner: reading csv: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("scanner: csv has no data rows")
	}
	header := map[string]int{}
	for i, h := range records[0] {
		header[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\uFEFF")))] = i
	}
	get := func(row []string, names ...string) string {
		for _, n := range names {
			if i, ok := header[strings.ToLower(n)]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
		}
		return ""
	}
	var out []Finding
	for _, row := range records[1:] {
		var f Finding
		switch format {
		case "nessus":
			f = Finding{Source: "nessus", Host: get(row, "Host"), CVE: get(row, "CVE"), Severity: normalizeSeverity(get(row, "Risk")),
				Title: get(row, "Name"), Port: get(row, "Port"), PluginID: get(row, "Plugin ID"), Description: get(row, "Synopsis")}
			f.CVSS = parseFloat(get(row, "CVSS v3.0 Base Score", "CVSS v2.0 Base Score", "CVSS"))
		case "qualys":
			host := get(row, "DNS", "FQDN")
			if host == "" {
				host = get(row, "IP")
			}
			f = Finding{Source: "qualys", Host: host, CVE: get(row, "CVE ID"), Severity: qualysSeverity(get(row, "Severity")),
				Title: get(row, "Title"), Port: get(row, "Port"), PluginID: get(row, "QID"), Description: get(row, "Threat")}
			f.CVSS = parseFloat(get(row, "CVSS3 Base", "CVSS Base", "CVSS"))
		case "generic":
			f = Finding{Source: "generic", Host: get(row, "host"), CVE: get(row, "cve"), Severity: normalizeSeverity(get(row, "severity")),
				Title: get(row, "title", "name"), Port: get(row, "port"), Description: get(row, "description")}
			f.CVSS = parseFloat(get(row, "cvss"))
		default:
			return nil, fmt.Errorf("scanner: unknown format %q (want nessus, qualys or generic)", format)
		}
		if f.Host == "" || (f.Title == "" && f.CVE == "") {
			continue
		}
		if f.Severity == "" || f.Severity == "info" || f.Severity == "none" {
			continue // informational plugins aren't findings
		}
		// Nessus lists one CVE per row but can pack several with commas;
		// keep the first and note the rest in the title
		if i := strings.IndexAny(f.CVE, ", "); i > 0 {
			f.CVE = f.CVE[:i]
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("scanner: no usable findings in csv (check the format and that Host/Risk-Severity columns are present)")
	}
	return out, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "4", "5":
		return "critical"
	case "high", "3":
		return "high"
	case "medium", "moderate", "2":
		return "medium"
	case "low", "1":
		return "low"
	case "info", "informational", "none", "0", "":
		return "info"
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// qualysSeverity maps Qualys's 1-5 scale.
func qualysSeverity(s string) string {
	switch strings.TrimSpace(s) {
	case "5":
		return "critical"
	case "4":
		return "high"
	case "3":
		return "medium"
	case "2":
		return "low"
	default:
		return "info"
	}
}

func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(strings.TrimSpace(s), "%f", &f)
	return f
}

// Match groups findings by Muster host name. hosts maps every known
// host name to its IPv4 addresses (from network_interfaces facts) so a
// scanner that names hosts by IP or FQDN still lands. Unmatched
// findings come back grouped by the scanner's own name for them.
func Match(findings []Finding, hosts map[string][]string) (matched map[string][]Finding, unmatched map[string][]Finding) {
	matched, unmatched = map[string][]Finding{}, map[string][]Finding{}
	byKey := map[string]string{}
	for name, addrs := range hosts {
		byKey[strings.ToLower(name)] = name
		byKey[strings.ToLower(strings.SplitN(name, ".", 2)[0])] = name
		for _, a := range addrs {
			byKey[a] = name
		}
	}
	for _, f := range findings {
		key := strings.ToLower(f.Host)
		target, ok := byKey[key]
		if !ok {
			if ip := net.ParseIP(f.Host); ip == nil {
				target, ok = byKey[strings.SplitN(key, ".", 2)[0]]
			}
		}
		if ok {
			matched[target] = append(matched[target], f)
		} else {
			unmatched[f.Host] = append(unmatched[f.Host], f)
		}
	}
	for _, list := range matched {
		sort.SliceStable(list, func(i, j int) bool { return rank(list[i].Severity) < rank(list[j].Severity) })
	}
	return matched, unmatched
}

func rank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}

// ToFact renders a host's findings as the scanner_findings fact data.
func ToFact(source string, findings []Finding) map[string]any {
	items := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		items = append(items, map[string]any{
			"cve": f.CVE, "severity": f.Severity, "title": f.Title, "port": f.Port, "cvss": f.CVSS,
			"plugin_id": f.PluginID, "source": f.Source, "description": f.Description,
		})
	}
	return map[string]any{"count": len(items), "items": items, "source": source}
}

// FromFact converts a scanner_findings fact's Data["items"] back into
// vuln.Findings so imported results ride the same compliance, risk and
// summary paths as Muster's own version matching. The package column
// carries the scanner title (there is no package for a network finding)
// and Source records which scanner reported it.
func FromFact(itemsRaw any) []vuln.Finding {
	var items []map[string]any
	switch v := itemsRaw.(type) {
	case []any:
		for _, raw := range v {
			if m, ok := raw.(map[string]any); ok {
				items = append(items, m)
			}
		}
	case []map[string]any:
		items = v
	}
	out := make([]vuln.Finding, 0, len(items))
	for _, m := range items {
		str := func(k string) string { s, _ := m[k].(string); return s }
		pkg := str("title")
		if port := str("port"); port != "" {
			pkg += " (port " + port + ")"
		}
		src := str("source")
		if src == "" {
			src = "scanner"
		}
		out = append(out, vuln.Finding{
			Package:     pkg,
			CVE:         str("cve"),
			Severity:    str("severity"),
			Description: str("description"),
			Source:      src,
		})
	}
	return out
}
