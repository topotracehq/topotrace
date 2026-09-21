/*******************************************************************************
 * @file         eol.go
 * @brief        Package eol answers "is this host's operating system still supported?" from its system_summary fact, against a small built-in table of vendor end-of-support dates.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package eol answers "is this host's operating system still supported?"
// from its system_summary fact, against a small built-in table of
// vendor end-of-support dates. An OS past its end of life gets no
// security patches at all, which makes every other finding on the host
// worse -- so it's its own compliance check, its own risk factor, and
// its own Fleet tile rather than a line buried in a facts table.
//
// The table is hand-maintained from vendors' published lifecycle pages
// (Ubuntu: standard support without ESM; Windows: mainstream+extended
// end for the consumer/client editions, extended end for Server; macOS:
// Apple publishes no dates, so the entries here follow its observed
// "current release plus two" practice and are marked as estimates). It
// is deliberately small and deliberately dated: check the dates against
// the vendor before relying on one, and add a row when a new release
// ships.
package eol

import (
	"fmt"
	"strings"
	"time"
)

// Entry is one product release and when its vendor stops supporting it.
type Entry struct {
	Product   string    // "Ubuntu", "Windows", "Windows Server", "Debian", "macOS", ...
	Version   string    // the version prefix matched against the host's reported version
	EOL       time.Time // end of standard support
	Estimated bool      // true when the vendor publishes no date (macOS)
}

func d(y int, m time.Month, day int) time.Time { return time.Date(y, m, day, 0, 0, 0, 0, time.UTC) }

// Table is the built-in lifecycle data -- see the package doc.
var Table = []Entry{
	{Product: "Ubuntu", Version: "16.04", EOL: d(2021, time.April, 30)},
	{Product: "Ubuntu", Version: "18.04", EOL: d(2023, time.May, 31)},
	{Product: "Ubuntu", Version: "20.04", EOL: d(2025, time.May, 31)},
	{Product: "Ubuntu", Version: "22.04", EOL: d(2027, time.June, 1)},
	{Product: "Ubuntu", Version: "24.04", EOL: d(2029, time.May, 31)},
	{Product: "Ubuntu", Version: "24.10", EOL: d(2025, time.July, 10)},
	{Product: "Ubuntu", Version: "25.04", EOL: d(2026, time.January, 31)},
	{Product: "Debian", Version: "10", EOL: d(2022, time.September, 10)},
	{Product: "Debian", Version: "11", EOL: d(2024, time.August, 14)},
	{Product: "Debian", Version: "12", EOL: d(2026, time.June, 10)},
	{Product: "Debian", Version: "13", EOL: d(2028, time.August, 1)},
	{Product: "Windows", Version: "7", EOL: d(2020, time.January, 14)},
	{Product: "Windows", Version: "8.1", EOL: d(2023, time.January, 10)},
	{Product: "Windows", Version: "10", EOL: d(2025, time.October, 14)},
	{Product: "Windows", Version: "11", EOL: d(2031, time.October, 14)}, // per-feature-update dates are shorter; this is the platform's last known date
	{Product: "Windows Server", Version: "2012", EOL: d(2023, time.October, 10)},
	{Product: "Windows Server", Version: "2016", EOL: d(2027, time.January, 12)},
	{Product: "Windows Server", Version: "2019", EOL: d(2029, time.January, 9)},
	{Product: "Windows Server", Version: "2022", EOL: d(2031, time.October, 14)},
	{Product: "Windows Server", Version: "2025", EOL: d(2034, time.October, 10)},
	{Product: "macOS", Version: "12", EOL: d(2024, time.September, 16), Estimated: true},
	{Product: "macOS", Version: "13", EOL: d(2025, time.September, 15), Estimated: true},
	{Product: "macOS", Version: "14", EOL: d(2026, time.September, 14), Estimated: true},
	{Product: "macOS", Version: "15", EOL: d(2027, time.September, 13), Estimated: true},
	{Product: "macOS", Version: "26", EOL: d(2028, time.September, 11), Estimated: true},
}

// EndingSoon is how far ahead of the EOL date a host is flagged.
const EndingSoon = 180 * 24 * time.Hour

// Status is the verdict for one host.
type Status struct {
	Product   string    `json:"product,omitempty"`
	Version   string    `json:"version,omitempty"`
	EOL       time.Time `json:"eol,omitempty"`
	Estimated bool      `json:"estimated,omitempty"`
	// State is "eol" (past the date), "ending-soon" (within EndingSoon),
	// "supported", or "unknown" (no table entry for this OS/version).
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// Check reads a system_summary fact's data (os, distribution,
// distribution_version) and returns the host's lifecycle status as of now.
func Check(summary map[string]any, now time.Time) Status {
	osName, _ := summary["os"].(string)
	distro, _ := summary["distribution"].(string)
	version, _ := summary["distribution_version"].(string)
	product, ver := normalize(osName, distro, version)
	if product == "" {
		return Status{State: "unknown", Detail: "no lifecycle data for " + strings.TrimSpace(distro+" "+version)}
	}
	for _, e := range Table {
		if e.Product != product || !strings.HasPrefix(ver, e.Version) {
			continue
		}
		// "10" must not match "10.x" of a different product line, and
		// "2012" must not match "2012 R2"'s sibling entries incorrectly --
		// prefix plus a boundary check keeps 11 from matching 1.
		rest := strings.TrimPrefix(ver, e.Version)
		if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			continue
		}
		st := Status{Product: product, Version: e.Version, EOL: e.EOL, Estimated: e.Estimated}
		days := int(e.EOL.Sub(now).Hours() / 24)
		est := ""
		if e.Estimated {
			est = " (estimated -- Apple publishes no dates)"
		}
		switch {
		case now.After(e.EOL):
			st.State = "eol"
			st.Detail = fmt.Sprintf("%s %s reached end of support on %s, %d days ago%s", product, e.Version, e.EOL.Format("Jan 2, 2006"), -days, est)
		case days <= int(EndingSoon.Hours()/24):
			st.State = "ending-soon"
			st.Detail = fmt.Sprintf("%s %s support ends %s, in %d days%s", product, e.Version, e.EOL.Format("Jan 2, 2006"), days, est)
		default:
			st.State = "supported"
			st.Detail = fmt.Sprintf("%s %s supported until %s%s", product, e.Version, e.EOL.Format("Jan 2, 2006"), est)
		}
		return st
	}
	return Status{Product: product, State: "unknown", Detail: fmt.Sprintf("no lifecycle entry for %s %s", product, ver)}
}

// normalize maps the loosely-formatted summary fields onto Table's
// Product/Version vocabulary.
func normalize(osName, distro, version string) (string, string) {
	dl := strings.ToLower(distro)
	switch {
	case strings.Contains(dl, "ubuntu"):
		return "Ubuntu", strings.Fields(version + " ")[0]
	case strings.Contains(dl, "debian"):
		return "Debian", strings.Fields(version + " ")[0]
	case strings.Contains(dl, "windows server"):
		// "Microsoft Windows Server 2019 Standard" -> "2019"
		for _, f := range strings.Fields(distro) {
			if len(f) == 4 && f[0] == '2' {
				return "Windows Server", f
			}
		}
		return "Windows Server", ""
	case strings.Contains(dl, "windows"):
		// "Microsoft Windows 10 Enterprise" -> "10"
		fields := strings.Fields(distro)
		for i, f := range fields {
			if strings.EqualFold(f, "windows") && i+1 < len(fields) {
				return "Windows", fields[i+1]
			}
		}
		return "Windows", ""
	case strings.EqualFold(osName, "darwin") || strings.Contains(dl, "macos") || strings.Contains(dl, "mac os"):
		// "14.5" -> "14"
		return "macOS", strings.SplitN(version, ".", 2)[0]
	}
	return "", ""
}
