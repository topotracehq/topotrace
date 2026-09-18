/*******************************************************************************
 * @file         sprawl.go
 * @brief        Package sprawl rolls the fleet's installed software up against a small catalog of commercial and SaaS desktop products, so the question "what are we paying for, how many seats of it are actually deployed, and how many different tools do ...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package sprawl rolls the fleet's installed software up against a
// small catalog of commercial and SaaS desktop products, so the
// question "what are we paying for, how many seats of it are actually
// deployed, and how many different tools do we have doing the same
// job" has an answer. Security and finance ask the same inventory
// different questions; this is the finance-shaped one, built from the
// same installed_software facts the security checks use.
//
// The catalog is illustrative and hand-authored (product name patterns,
// a category, whether it's typically licensed per seat) -- the seam an
// operator's real license inventory or a SAM tool's export would plug
// into. Matching is case-insensitive substring on the package name, so
// vendor-versioned names ("Adobe Acrobat DC (64-bit)") still match.
package sprawl

import (
	"sort"
	"strings"
)

// Product is one catalog entry. Category groups products that do the
// same job, so two products in one category on the same fleet is an
// overlap worth a look ("containers", "video-conferencing", ...).
type Product struct {
	Name     string   // display name
	Match    []string // case-insensitive substrings of installed_software names
	Category string   // "collaboration", "video-conferencing", "creative", "developer", "productivity", "security", "remote-access", "virtualization"
	Licensed bool     // true when the product is typically bought per seat
}

// Catalog is the built-in product list -- see the package doc.
var Catalog = []Product{
	{Name: "Microsoft 365", Match: []string{"microsoft 365", "office 365", "microsoft office"}, Category: "productivity", Licensed: true},
	{Name: "Adobe Acrobat", Match: []string{"adobe acrobat"}, Category: "creative", Licensed: true},
	{Name: "Adobe Creative Cloud", Match: []string{"adobe creative cloud", "adobe photoshop", "adobe illustrator", "adobe premiere"}, Category: "creative", Licensed: true},
	{Name: "Slack", Match: []string{"slack"}, Category: "collaboration", Licensed: true},
	{Name: "Microsoft Teams", Match: []string{"microsoft teams", "teams machine-wide"}, Category: "video-conferencing", Licensed: true},
	{Name: "Zoom", Match: []string{"zoom"}, Category: "video-conferencing", Licensed: true},
	{Name: "Webex", Match: []string{"webex"}, Category: "video-conferencing", Licensed: true},
	{Name: "Docker Desktop", Match: []string{"docker desktop"}, Category: "containers", Licensed: true},
	{Name: "JetBrains IDEs", Match: []string{"intellij", "pycharm", "goland", "webstorm", "rider", "jetbrains"}, Category: "developer", Licensed: true},
	{Name: "Visual Studio", Match: []string{"visual studio 20", "visual studio professional", "visual studio enterprise"}, Category: "developer", Licensed: true},
	{Name: "Visual Studio Code", Match: []string{"visual studio code", "code -", "vscode"}, Category: "developer", Licensed: false},
	{Name: "Tableau", Match: []string{"tableau"}, Category: "productivity", Licensed: true},
	{Name: "Parallels Desktop", Match: []string{"parallels"}, Category: "virtualization", Licensed: true},
	{Name: "VMware Workstation/Fusion", Match: []string{"vmware workstation", "vmware fusion"}, Category: "virtualization", Licensed: true},
	{Name: "TeamViewer", Match: []string{"teamviewer"}, Category: "remote-access", Licensed: true},
	{Name: "AnyDesk", Match: []string{"anydesk"}, Category: "remote-access", Licensed: true},
	{Name: "1Password", Match: []string{"1password"}, Category: "security", Licensed: true},
	{Name: "LastPass", Match: []string{"lastpass"}, Category: "security", Licensed: true},
	{Name: "Bitwarden", Match: []string{"bitwarden"}, Category: "security", Licensed: false},
	{Name: "Dropbox", Match: []string{"dropbox"}, Category: "collaboration", Licensed: true},
	{Name: "Box", Match: []string{"box drive", "box sync"}, Category: "collaboration", Licensed: true},
	{Name: "Google Drive", Match: []string{"google drive"}, Category: "collaboration", Licensed: false},
	{Name: "Camtasia / Snagit", Match: []string{"camtasia", "snagit"}, Category: "creative", Licensed: true},
	{Name: "Notion", Match: []string{"notion"}, Category: "productivity", Licensed: true},
	{Name: "Figma", Match: []string{"figma"}, Category: "creative", Licensed: true},
}

// Install is one product seen on the fleet.
type Install struct {
	Product  string   `json:"product"`
	Category string   `json:"category"`
	Licensed bool     `json:"licensed"`
	Hosts    []string `json:"hosts"`
	Seats    int      `json:"seats"` // len(Hosts)
}

// Overlap is a category served by more than one product -- the
// "three video-conferencing tools" finding.
type Overlap struct {
	Category string   `json:"category"`
	Products []string `json:"products"`
	Seats    int      `json:"seats"`
}

// Report is the fleet rollup.
type Report struct {
	Installs      []Install `json:"installs"`
	Overlaps      []Overlap `json:"overlaps"`
	LicensedSeats int       `json:"licensed_seats"`
	HostsCovered  int       `json:"hosts_covered"` // hosts with at least one catalog match
	TotalHosts    int       `json:"total_hosts"`
}

// HostSoftware is the input: host name -> installed package names.
type HostSoftware map[string][]string

// Rollup matches every host's software against the Catalog.
func Rollup(fleet HostSoftware) Report {
	byProduct := map[string]map[string]bool{}
	covered := map[string]bool{}
	for host, names := range fleet {
		for _, n := range names {
			ln := strings.ToLower(n)
			for _, p := range Catalog {
				for _, m := range p.Match {
					if strings.Contains(ln, m) {
						if byProduct[p.Name] == nil {
							byProduct[p.Name] = map[string]bool{}
						}
						byProduct[p.Name][host] = true
						covered[host] = true
						break
					}
				}
			}
		}
	}
	rep := Report{TotalHosts: len(fleet), HostsCovered: len(covered), Installs: []Install{}, Overlaps: []Overlap{}}
	byCategory := map[string][]string{}
	catSeats := map[string]int{}
	for _, p := range Catalog {
		hosts := byProduct[p.Name]
		if len(hosts) == 0 {
			continue
		}
		list := make([]string, 0, len(hosts))
		for h := range hosts {
			list = append(list, h)
		}
		sort.Strings(list)
		rep.Installs = append(rep.Installs, Install{Product: p.Name, Category: p.Category, Licensed: p.Licensed, Hosts: list, Seats: len(list)})
		if p.Licensed {
			rep.LicensedSeats += len(list)
		}
		byCategory[p.Category] = append(byCategory[p.Category], p.Name)
		catSeats[p.Category] += len(list)
	}
	sort.SliceStable(rep.Installs, func(i, j int) bool { return rep.Installs[i].Seats > rep.Installs[j].Seats })
	for cat, products := range byCategory {
		if len(products) > 1 {
			rep.Overlaps = append(rep.Overlaps, Overlap{Category: cat, Products: products, Seats: catSeats[cat]})
		}
	}
	sort.Slice(rep.Overlaps, func(i, j int) bool { return rep.Overlaps[i].Category < rep.Overlaps[j].Category })
	return rep
}
