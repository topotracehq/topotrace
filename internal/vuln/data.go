/*******************************************************************************
 * @file         data.go
 * @brief        Package vuln does small, honest vulnerability correlation against Muster's own installed_software fact category.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package vuln does small, honest vulnerability correlation against
// Muster's own installed_software fact category. Dataset below is a
// curated, static list of well-known package/version combinations
// bundled into the binary -- not a live feed, and not remotely close to
// full NVD/OSV coverage. This is a deliberately small demonstration of
// the concept (turning a plain software inventory into an actual
// vulnerability signal), not a claim of real CVE-feed coverage -- see
// the README's caveat. A real version of this feature would sync a
// feed like OSV or the NVD API on a schedule; this one never reaches
// the network at all, matching every other "honest about its limits"
// piece of this project.
package vuln

// Entry is one known-vulnerable package/version-ceiling pair.
type Entry struct {
	Package     string `json:"package"`
	MaxVersion  string `json:"max_vulnerable_version"` // inclusive: any installed version <= this is flagged
	CVE         string `json:"cve"`
	Severity    string `json:"severity"` // "low", "medium", "high", "critical"
	Description string `json:"description"`
}

// Dataset is intentionally small and hand-picked from well-documented,
// real CVEs against common Debian/Ubuntu packages -- a realistic
// illustration, not an attempt at a comprehensive feed.
var Dataset = []Entry{
	{Package: "bash", MaxVersion: "4.3.25", CVE: "CVE-2014-6271", Severity: "critical", Description: "Shellshock: arbitrary code execution via a crafted environment variable"},
	{Package: "sudo", MaxVersion: "1.9.5", CVE: "CVE-2021-3156", Severity: "high", Description: "Heap-based buffer overflow (\"Baron Samedit\") allowing privilege escalation"},
	{Package: "openssh-server", MaxVersion: "9.3", CVE: "CVE-2023-38408", Severity: "critical", Description: "Remote code execution via a forwarded ssh-agent socket"},
	{Package: "openssl", MaxVersion: "1.1.1n", CVE: "CVE-2022-0778", Severity: "high", Description: "Infinite loop in BN_mod_sqrt() reachable via a crafted certificate"},
	{Package: "libssl1.1", MaxVersion: "1.1.1n", CVE: "CVE-2022-0778", Severity: "high", Description: "Infinite loop in BN_mod_sqrt() reachable via a crafted certificate"},
	{Package: "curl", MaxVersion: "7.83.1", CVE: "CVE-2022-32221", Severity: "medium", Description: "POST-following-PUT request confusion leading to information disclosure"},
	{Package: "libcurl4", MaxVersion: "7.83.1", CVE: "CVE-2022-32221", Severity: "medium", Description: "POST-following-PUT request confusion leading to information disclosure"},
	{Package: "zlib1g", MaxVersion: "1.2.11", CVE: "CVE-2018-25032", Severity: "medium", Description: "Memory corruption via crafted deflate input"},
	{Package: "sqlite3", MaxVersion: "3.31.1", CVE: "CVE-2021-36690", Severity: "medium", Description: "NULL pointer dereference via a crafted SQL query"},
	{Package: "apt", MaxVersion: "1.8.0", CVE: "CVE-2019-3462", Severity: "high", Description: "HTTP redirect handling allows content injection during package installation"},
}
