/*******************************************************************************
 * @file         entitygraph_test.go
 * @brief        Tests for the Muster entitygraph package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package entitygraph

import (
	"math"
	"testing"
	"time"

	"muster/internal/allowlist"
	"muster/internal/browserext"
	"muster/internal/certs"
	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/vuln"
)

// fixture builds two hosts that deliberately share a package, a CVE and
// an extension, so the cross-links the graph exists to show are all
// present.
func fixture() ([]compliance.Input, []model.Rule, []model.SoftwareRule) {
	now := time.Now().UTC()
	shared := vuln.Finding{Package: "bash", Version: "4.3", CVE: "CVE-2014-6271", Severity: "critical",
		Description: "Shellshock"}
	ext := browserext.Finding{Extension: browserext.Extension{Browser: "chrome", ID: "extshared",
		Name: "Shared Extension", Version: "1.0"}, Level: "low"}
	risky := browserext.Finding{Extension: browserext.Extension{Browser: "chrome", ID: "extrisky",
		Name: "Risky Extension", Version: "2.0"}, Level: "high", Reasons: []string{"broad host permissions"}}

	a := compliance.Input{
		Host:              model.Host{Name: "a.prod", Platform: "linux", Group: "prod", LastCooked: now},
		Facts:             map[string]model.Fact{},
		VulnFindings:      []vuln.Finding{shared},
		BrowserExtensions: []browserext.Finding{ext, risky},
		Certificates: []certs.Cert{
			{ID: "/etc/ssl/a.pem", Subject: "CN = a.example.com", DaysLeft: 5, State: "expiring"},
			{ID: "/etc/ssl/fine.pem", Subject: "CN = fine.example.com", DaysLeft: 300, State: "ok"},
		},
	}
	b := compliance.Input{
		Host:  model.Host{Name: "b.eng", Platform: "linux", Group: "eng", LastCooked: now},
		Facts: map[string]model.Fact{},
		// same CVE via the same package, plus an imported scanner finding
		VulnFindings: []vuln.Finding{shared,
			{Package: "SSH Weak Algorithms (port 22)", CVE: "CVE-2016-2183", Severity: "medium", Source: "nessus"}},
		SoftwareViolations: []allowlist.Violation{{Rule: "Ban vsftpd", Kind: "deny", Package: "vsftpd", Version: "3.0"}},
		ShadowAIViolations: []allowlist.Violation{{Rule: "Ollama", Kind: "shadow_ai", Package: "ollama", Version: "0.1"}},
		BrowserExtensions:  []browserext.Finding{ext},
	}
	rules := []model.Rule{
		{ID: "r-global", Name: "Global posture floor", Kind: "posture_below", Threshold: 70},
		{ID: "r-prod", Name: "Prod only", Group: "prod", Kind: "stale"},
	}
	srules := []model.SoftwareRule{{ID: "s1", Name: "Ban vsftpd", Kind: "deny", Match: "vsftpd"}}
	return []compliance.Input{a, b}, rules, srules
}

func nodeByID(g Graph, id string) (Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func hasEdge(g Graph, from, to, kind string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

func TestBuildSharesEntitiesAcrossHosts(t *testing.T) {
	inputs, rules, srules := fixture()
	g := Build(inputs, rules, srules, Options{})

	// One node per shared entity, not one per host.
	if _, ok := nodeByID(g, "cve:cve-2014-6271"); !ok {
		t.Fatal("shared CVE should be a node")
	}
	count := 0
	for _, n := range g.Nodes {
		if n.Kind == "cve" && n.Label == "CVE-2014-6271" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared CVE should appear once, got %d", count)
	}

	// The package both hosts install links them through one node.
	pkg, ok := nodeByID(g, "pkg:bash")
	if !ok {
		t.Fatal("vulnerable package should be a node")
	}
	if !hasEdge(g, "host:a.prod", "pkg:bash", "installs") || !hasEdge(g, "host:b.eng", "pkg:bash", "installs") {
		t.Fatal("both hosts should edge to the shared package")
	}
	if !hasEdge(g, "pkg:bash", "cve:cve-2014-6271", "affected-by") {
		t.Fatal("package should edge to its CVE")
	}
	if pkg.Degree < 3 {
		t.Fatalf("shared package degree should count both hosts and the CVE, got %d", pkg.Degree)
	}

	// An imported finding has no package, so it hangs off the host.
	if !hasEdge(g, "host:b.eng", "cve:cve-2016-2183", "exposed-to") {
		t.Fatal("imported finding should edge straight to the host")
	}
	imported, _ := nodeByID(g, "cve:cve-2016-2183")
	if imported.Sub != "medium, via nessus" {
		t.Fatalf("imported CVE should name its scanner, got %q", imported.Sub)
	}
}

func TestBuildFiltersNoise(t *testing.T) {
	inputs, rules, srules := fixture()
	g := Build(inputs, rules, srules, Options{})

	// A healthy certificate is a degree-1 leaf that answers nothing.
	if _, ok := nodeByID(g, "cert:a.prod:/etc/ssl/fine.pem"); ok {
		t.Fatal("a healthy certificate should not be a node")
	}
	if n, ok := nodeByID(g, "cert:a.prod:/etc/ssl/a.pem"); !ok || n.Status != "warning" {
		t.Fatalf("an expiring certificate should be a warning node, got %+v ok=%v", n, ok)
	}

	// A low-risk extension on two hosts stays (it links them); a
	// low-risk extension on one host would not.
	if n, ok := nodeByID(g, "ext:extshared"); !ok {
		t.Fatal("an extension on two hosts should be a node even when harmless")
	} else if n.Status != "" {
		t.Fatalf("a low-risk extension should carry no status, got %q", n.Status)
	}
	if n, ok := nodeByID(g, "ext:extrisky"); !ok || n.Status != "critical" {
		t.Fatalf("a high-risk extension should be critical, got %+v ok=%v", n, ok)
	}
}

func TestRulesAttachToGroups(t *testing.T) {
	inputs, rules, srules := fixture()
	g := Build(inputs, rules, srules, Options{})

	// A scoped rule reaches one group; an unscoped one reaches all.
	if !hasEdge(g, "rule:r-prod", "group:prod", "governs") {
		t.Fatal("scoped rule should govern its own group")
	}
	if hasEdge(g, "rule:r-prod", "group:eng", "governs") {
		t.Fatal("scoped rule should not reach another group")
	}
	for _, gid := range []string{"group:prod", "group:eng"} {
		if !hasEdge(g, "rule:r-global", gid, "governs") {
			t.Fatalf("global rule should govern %s", gid)
		}
	}
	if !hasEdge(g, "srule:s1", "group:prod", "governs") {
		t.Fatal("global software rule should govern every group")
	}
}

func TestTypeFilterAndCounts(t *testing.T) {
	inputs, rules, srules := fixture()
	full := Build(inputs, rules, srules, Options{})
	only := Build(inputs, rules, srules, Options{Types: map[string]bool{"host": true, "group": true}})

	for _, n := range only.Nodes {
		if n.Kind != "host" && n.Kind != "group" {
			t.Fatalf("filtered graph should only hold hosts and groups, got %+v", n)
		}
	}
	// Counts always describe the whole fleet, so the filter row can
	// show what is available rather than what survived.
	if only.Counts["cve"] != full.Counts["cve"] || only.Counts["cve"] == 0 {
		t.Fatalf("counts should be pre-filter: %v vs %v", only.Counts, full.Counts)
	}
	for _, e := range only.Edges {
		if _, ok := nodeByID(only, e.From); !ok {
			t.Fatalf("edge %+v dangles", e)
		}
		if _, ok := nodeByID(only, e.To); !ok {
			t.Fatalf("edge %+v dangles", e)
		}
	}
}

func TestFocusNarrowsByDepth(t *testing.T) {
	inputs, rules, srules := fixture()

	one := Build(inputs, rules, srules, Options{Focus: "pkg:bash", Depth: 1})
	if len(one.Nodes) != 4 { // the package, both hosts, the CVE
		t.Fatalf("depth 1 from the shared package should hold 4 nodes, got %d", len(one.Nodes))
	}
	if one.Focus != "pkg:bash" {
		t.Fatalf("focus should echo back, got %q", one.Focus)
	}

	two := Build(inputs, rules, srules, Options{Focus: "pkg:bash", Depth: 2})
	if len(two.Nodes) <= len(one.Nodes) {
		t.Fatalf("depth 2 should reach further: %d vs %d", len(two.Nodes), len(one.Nodes))
	}
	if _, ok := nodeByID(two, "group:prod"); !ok {
		t.Fatal("depth 2 from the package should reach the hosts' groups")
	}

	// An unknown focus is ignored rather than returning nothing.
	all := Build(inputs, rules, srules, Options{Focus: "nope:nope"})
	if len(all.Nodes) != len(Build(inputs, rules, srules, Options{}).Nodes) {
		t.Fatal("an unknown focus should not narrow the graph")
	}
}

func TestMaxNodesKeepsTheSkeleton(t *testing.T) {
	inputs, rules, srules := fixture()
	g := Build(inputs, rules, srules, Options{MaxNodes: 6})
	if len(g.Nodes) != 6 {
		t.Fatalf("cap should be honored, got %d nodes", len(g.Nodes))
	}
	if g.Omitted == 0 {
		t.Fatal("capped graph should report what it dropped")
	}
	// Hosts, groups and rules are the skeleton and survive the cap.
	for _, id := range []string{"host:a.prod", "host:b.eng", "group:prod", "group:eng"} {
		if _, ok := nodeByID(g, id); !ok {
			t.Fatalf("%s should survive the node cap", id)
		}
	}
}

func TestLayoutIsDeterministicAndOnCanvas(t *testing.T) {
	inputs, rules, srules := fixture()
	a := Build(inputs, rules, srules, Options{})
	b := Build(inputs, rules, srules, Options{})
	if len(a.Nodes) != len(b.Nodes) {
		t.Fatal("same input should give the same node count")
	}
	for i := range a.Nodes {
		if a.Nodes[i].ID != b.Nodes[i].ID {
			t.Fatalf("node order should be stable: %s vs %s", a.Nodes[i].ID, b.Nodes[i].ID)
		}
		if a.Nodes[i].X != b.Nodes[i].X || a.Nodes[i].Y != b.Nodes[i].Y {
			t.Fatalf("layout should be deterministic, %s moved", a.Nodes[i].ID)
		}
	}
	for _, n := range a.Nodes {
		if math.IsNaN(n.X) || math.IsNaN(n.Y) {
			t.Fatalf("%s has a NaN position", n.ID)
		}
		if n.X < 0 || n.X > float64(a.Width) || n.Y < 0 || n.Y > float64(a.Height) {
			t.Fatalf("%s is off canvas at %.1f,%.1f", n.ID, n.X, n.Y)
		}
	}
	// No node may overlap another: the separation pass exists because
	// entities with identical neighborhoods (several fleet-wide rules
	// governing the same groups) otherwise settle on one point.
	for i := 0; i < len(a.Nodes); i++ {
		for j := i + 1; j < len(a.Nodes); j++ {
			dx := a.Nodes[i].X - a.Nodes[j].X
			dy := a.Nodes[i].Y - a.Nodes[j].Y
			gap := math.Sqrt(dx*dx+dy*dy) - a.Nodes[i].R - a.Nodes[j].R
			if gap < 1 {
				t.Fatalf("%s and %s overlap (gap %.1f)", a.Nodes[i].ID, a.Nodes[j].ID, gap)
			}
		}
	}
	// Labels are assigned to the best-connected nodes and never to two
	// nodes whose text would collide.
	labeled := 0
	for _, n := range a.Nodes {
		if n.ShowLabel {
			labeled++
		}
	}
	if labeled == 0 {
		t.Fatal("some nodes should carry a direct label")
	}
}

func TestEmptyAndSingle(t *testing.T) {
	if g := Build(nil, nil, nil, Options{}); len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Fatalf("empty fleet should give an empty graph, got %+v", g)
	}
	one := Build([]compliance.Input{{
		Host:  model.Host{Name: "solo", Platform: "linux", LastCooked: time.Now().UTC()},
		Facts: map[string]model.Fact{},
	}}, nil, nil, Options{Types: map[string]bool{"host": true}})
	if len(one.Nodes) != 1 {
		t.Fatalf("one host should give one node, got %d", len(one.Nodes))
	}
	if one.Nodes[0].X != float64(one.Width)/2 || one.Nodes[0].Y != float64(one.Height)/2 {
		t.Fatalf("a lone node belongs in the middle, got %.1f,%.1f", one.Nodes[0].X, one.Nodes[0].Y)
	}
}

func TestNeighborsGroupsByEdgeKind(t *testing.T) {
	inputs, rules, srules := fixture()
	g := Build(inputs, rules, srules, Options{})
	rels := g.Neighbors("host:a.prod")
	if len(rels) == 0 {
		t.Fatal("a host should have relations")
	}
	rank := map[string]int{}
	for i, k := range EdgeKinds {
		rank[k] = i
	}
	last := -1
	for _, r := range rels {
		if rank[r.Kind] < last {
			t.Fatalf("relations should come back in EdgeKinds order, %s out of place", r.Kind)
		}
		last = rank[r.Kind]
		if r.Other.ID == "host:a.prod" {
			t.Fatal("a node should not be its own neighbor")
		}
		if r.Direction != "in" && r.Direction != "out" {
			t.Fatalf("direction should be in or out, got %q", r.Direction)
		}
	}
	if len(g.Neighbors("nope")) != 0 {
		t.Fatal("an unknown node has no neighbors")
	}
}

func TestEveryKindHasAFamily(t *testing.T) {
	for _, k := range Kinds {
		if Families[k] == "" {
			t.Fatalf("kind %q has no family", k)
		}
	}
	// Three families, because a node-link diagram cannot carry more
	// than three categorical hues and still separate every pair.
	fams := map[string]bool{}
	for _, f := range Families {
		fams[f] = true
	}
	if len(fams) != 3 {
		t.Fatalf("expected 3 families, got %d: %v", len(fams), fams)
	}
}

func TestContractionRescuesFilteredRelationships(t *testing.T) {
	inputs, rules, srules := fixture()

	// Hosts and CVEs alone: the package that joins them is gone, so
	// without contraction the shared Shellshock finding would show no
	// connection to either host at all.
	g := Build(inputs, rules, srules, Options{Types: map[string]bool{"host": true, "cve": true}})
	for _, h := range []string{"host:a.prod", "host:b.eng"} {
		if !hasEdge(g, h, "cve:cve-2014-6271", "indirect") && !hasEdge(g, "cve:cve-2014-6271", h, "indirect") {
			t.Fatalf("%s should reach the shared CVE through a contracted edge", h)
		}
	}
	// A real edge is never relabeled as indirect.
	if hasEdge(g, "host:b.eng", "cve:cve-2016-2183", "indirect") {
		t.Fatal("a direct edge should stay direct")
	}
	if !hasEdge(g, "host:b.eng", "cve:cve-2016-2183", "exposed-to") {
		t.Fatal("the direct imported-finding edge should survive the filter")
	}
	// Contraction never joins two nodes of the same family, so a
	// package shared by many hosts does not become a host-to-host mesh.
	for _, e := range g.Edges {
		if e.Kind != "indirect" {
			continue
		}
		from, _ := nodeByID(g, e.From)
		to, _ := nodeByID(g, e.To)
		if from.Family == to.Family {
			t.Fatalf("contracted edge joins one family: %+v", e)
		}
	}
	// No contraction happens on an unfiltered graph.
	for _, e := range Build(inputs, rules, srules, Options{}).Edges {
		if e.Kind == "indirect" {
			t.Fatalf("unfiltered graph should have no contracted edges, got %+v", e)
		}
	}
}
