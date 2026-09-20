/*******************************************************************************
 * @file         entitygraph.go
 * @brief        Package entitygraph builds the fleet's entity relationship map: not the network picture internal/graph draws (hosts and discovered assets grouped by subnet), but the data-level one -- hosts, board groups, notable software packages, CVEs,...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package entitygraph builds the fleet's entity relationship map: not
// the network picture internal/graph draws (hosts and discovered assets
// grouped by subnet), but the data-level one -- hosts, board groups,
// notable software packages, CVEs, TLS certificates, browser
// extensions, and the policy and software rules that govern them, all
// as typed nodes joined by typed edges.
//
// The point is the questions a list cannot answer: which hosts share
// this CVE, which packages carry it, what does this one rule actually
// touch, which extension is on half the fleet. Every relationship here
// already existed somewhere in Muster; this package is the one place
// they are assembled into a single traversable structure.
//
// Two design constraints shape it.
//
// First, noise. A fleet of fifteen hosts carries thousands of installed
// packages, and a node per package per host is an unreadable hairball
// that answers nothing. So a package earns a node only by being
// notable: it carries a known vulnerability, it violates a software
// rule, it matches a shadow-AI signature, or it is a licensed product
// in internal/sprawl's catalog. Certificates appear only when they are
// expiring or expired, and extensions only when they are risky or
// installed on more than one host. Everything included is either
// something an operator would act on or something that links two hosts
// together.
//
// Second, determinism. Layout is computed here, server-side, by a
// fixed-iteration force-directed relaxation with no randomness at all
// (initial positions come from a stable sort, not a seed), so the same
// fleet always produces the same picture and the client only draws.
// Same division of labor as internal/graph.
package entitygraph

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"muster/internal/certs"
	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/risk"
	"muster/internal/sprawl"
)

// Kinds are the entity kinds a node can be, in the order the legend
// should list them. Kind drives the shape the dashboard draws.
var Kinds = []string{"host", "group", "package", "cve", "certificate", "extension", "rule"}

// Families group the kinds into the three things a reader is actually
// looking for: what we own, what is wrong with it, and what we decided
// about it. Family drives color; kind drives shape.
//
// Three is not an aesthetic choice. In a node-link diagram any two
// nodes can end up adjacent, so a categorical palette has to separate
// every pair, not just neighbors in a legend order -- and past three
// hues no ordering clears the colorblind-separation floor. Encoding
// seven kinds by hue would have failed that check; encoding three
// families by hue and the kind by shape passes it, and keeps the
// reserved status colors free to mean status.
var Families = map[string]string{
	"host": "asset", "group": "asset", "package": "asset",
	"cve": "finding", "certificate": "finding", "extension": "finding",
	"rule": "policy",
}

// EdgeKinds are the relationship types, in legend order.
var EdgeKinds = []string{"member", "installs", "affected-by", "exposed-to", "presents", "governs", "indirect"}

// Node is one entity.
type Node struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Family string `json:"family"`
	Label  string `json:"label"`
	Sub    string `json:"sub,omitempty"`
	// Status is "", "warning" or "critical" -- drawn as a ring, never
	// as the node's own color, and always restated in the node's text
	// so it never reads as color alone.
	Status string  `json:"status,omitempty"`
	Detail string  `json:"detail,omitempty"`
	Href   string  `json:"href,omitempty"`
	Degree int     `json:"degree"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	R      float64 `json:"r"`
	// ShowLabel is false when this node's direct label would collide
	// with one already placed. Labels are assigned in importance order
	// (most connected first) so the hubs keep theirs; the rest are
	// reachable by hover, by focusing the node, and in the table view.
	ShowLabel bool `json:"show_label"`
	// LabelAnchor is where the label sits relative to the node:
	// "below" (the default reading position), "above", "right" or
	// "left", whichever was free.
	LabelAnchor string `json:"label_anchor,omitempty"`
}

// Edge is one relationship. From and To are node IDs.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// Graph is the whole map plus what it took to fit it on a canvas.
type Graph struct {
	Nodes  []Node `json:"nodes"`
	Edges  []Edge `json:"edges"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	// Counts is how many nodes of each kind the full fleet produced,
	// before any type filter or node cap -- so the dashboard's filter
	// row can show what is available, not just what is drawn.
	Counts map[string]int `json:"counts"`
	// Omitted is how many nodes the MaxNodes cap dropped.
	Omitted int `json:"omitted,omitempty"`
	// Focus echoes back the node the graph was narrowed to, if any.
	Focus string `json:"focus,omitempty"`
}

// Options narrows what Build returns.
type Options struct {
	// Types, when non-empty, keeps only these kinds.
	Types map[string]bool
	// Focus, when set to a node ID, keeps only nodes within Depth hops
	// of it.
	Focus string
	// Depth is how far Focus reaches; <= 0 means 1.
	Depth int
	// MaxNodes caps the node count; <= 0 means DefaultMaxNodes.
	MaxNodes int
}

// DefaultMaxNodes is the cap Build applies when Options.MaxNodes is
// unset -- enough for a real fleet's notable entities, small enough
// that the layout relaxation stays instant and the picture stays
// readable.
const DefaultMaxNodes = 300

// builder accumulates nodes and edges while keeping insertion
// idempotent (many hosts install the same package).
type builder struct {
	nodes map[string]*Node
	edges map[string]Edge
}

func (b *builder) node(n Node) {
	if existing, ok := b.nodes[n.ID]; ok {
		// A shared entity keeps the worst status it was seen with, so
		// one host's expiring certificate is not hidden by another's
		// healthy one.
		if rankStatus(n.Status) > rankStatus(existing.Status) {
			existing.Status, existing.Detail = n.Status, n.Detail
		}
		return
	}
	n.Family = Families[n.Kind]
	copied := n
	b.nodes[n.ID] = &copied
}

func (b *builder) edge(from, to, kind string) {
	if from == to || from == "" || to == "" {
		return
	}
	b.edges[from+"\x00"+to+"\x00"+kind] = Edge{From: from, To: to, Kind: kind}
}

func rankStatus(s string) int {
	switch s {
	case "critical":
		return 2
	case "warning":
		return 1
	}
	return 0
}

// Build assembles the graph from every host's signals plus the
// operator's rules.
func Build(inputs []compliance.Input, rules []model.Rule, softwareRules []model.SoftwareRule, opts Options) Graph {
	b := &builder{nodes: map[string]*Node{}, edges: map[string]Edge{}}

	// An extension linking two hosts is interesting even when it is
	// harmless, so count hosts per extension before deciding what to
	// include.
	extHosts := map[string]int{}
	for _, in := range inputs {
		seen := map[string]bool{}
		for _, e := range in.BrowserExtensions {
			if e.ID != "" && !seen[e.ID] {
				extHosts[e.ID]++
				seen[e.ID] = true
			}
		}
	}

	groupOf := func(h model.Host) string {
		if h.Group == "" {
			return "(ungrouped)"
		}
		return h.Group
	}

	for _, in := range inputs {
		hostID := "host:" + in.Host.Name
		r := risk.Compute(in)
		hn := Node{ID: hostID, Kind: "host", Label: in.Host.Name, Sub: in.Host.Platform,
			Href: "#/host/" + in.Host.Name}
		switch {
		case in.Stale:
			hn.Status, hn.Detail = "critical", "not reporting"
		case r.Level == "critical" || r.Level == "high":
			hn.Status, hn.Detail = "critical", fmt.Sprintf("%s risk (score %d)", r.Level, r.Score)
		case r.Level == "medium":
			hn.Status, hn.Detail = "warning", fmt.Sprintf("medium risk (score %d)", r.Score)
		}
		b.node(hn)

		// group membership
		g := groupOf(in.Host)
		groupID := "group:" + g
		b.node(Node{ID: groupID, Kind: "group", Label: g, Sub: "board group"})
		b.edge(hostID, groupID, "member")

		// notable packages: vulnerable, denied, shadow AI, or licensed
		reasons := map[string]map[string]bool{} // package name -> reason set
		addReason := func(pkg, reason string) {
			pkg = strings.TrimSpace(pkg)
			if pkg == "" {
				return
			}
			if reasons[pkg] == nil {
				reasons[pkg] = map[string]bool{}
			}
			reasons[pkg][reason] = true
		}
		for _, f := range in.VulnFindings {
			if f.Source == "" {
				addReason(f.Package, "vulnerable")
			}
		}
		for _, v := range in.SoftwareViolations {
			if v.Kind == "deny" {
				addReason(v.Package, "denied")
			} else {
				addReason(v.Package, "not on allowlist")
			}
		}
		for _, v := range in.ShadowAIViolations {
			addReason(v.Package, "shadow AI")
		}
		for _, name := range licensedProducts(in) {
			addReason(name, "licensed product")
		}

		pkgID := func(name string) string { return "pkg:" + strings.ToLower(strings.TrimSpace(name)) }
		names := make([]string, 0, len(reasons))
		for name := range reasons {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			set := reasons[name]
			why := make([]string, 0, len(set))
			for reason := range set {
				why = append(why, reason)
			}
			sort.Strings(why)
			pn := Node{ID: pkgID(name), Kind: "package", Label: name, Sub: strings.Join(why, ", ")}
			switch {
			case set["denied"]:
				pn.Status, pn.Detail = "critical", "denied by a software rule"
			case set["shadow AI"], set["not on allowlist"]:
				pn.Status, pn.Detail = "warning", pn.Sub
			}
			b.node(pn)
			b.edge(hostID, pn.ID, "installs")
		}

		// CVEs: Muster's own matches hang off the package they were
		// found in; imported scanner findings have no package, so they
		// hang off the host directly.
		for _, f := range in.VulnFindings {
			label := f.CVE
			if label == "" {
				label = f.Package
			}
			if label == "" {
				continue
			}
			cn := Node{ID: "cve:" + strings.ToLower(label), Kind: "cve", Label: label, Sub: f.Severity}
			switch f.Severity {
			case "critical", "high":
				cn.Status, cn.Detail = "critical", f.Severity+" severity"
			case "medium":
				cn.Status, cn.Detail = "warning", "medium severity"
			}
			if f.Source != "" {
				cn.Sub = f.Severity + ", via " + f.Source
			}
			b.node(cn)
			if f.Source == "" && reasons[strings.TrimSpace(f.Package)] != nil {
				b.edge(pkgID(f.Package), cn.ID, "affected-by")
			} else {
				b.edge(hostID, cn.ID, "exposed-to")
			}
		}

		// certificates worth knowing about
		for _, c := range certs.Problems(in.Certificates) {
			label := c.Subject
			if label == "" {
				label = c.ID
			}
			cn := Node{ID: "cert:" + in.Host.Name + ":" + c.ID, Kind: "certificate", Label: label,
				Sub: fmt.Sprintf("%d days left", c.DaysLeft), Detail: c.Detail}
			if c.State == "expired" {
				cn.Status, cn.Sub = "critical", "expired"
			} else {
				cn.Status = "warning"
			}
			b.node(cn)
			b.edge(hostID, cn.ID, "presents")
		}

		// extensions: risky, or shared across hosts
		for _, e := range in.BrowserExtensions {
			if e.ID == "" || (e.Level == "low" && extHosts[e.ID] < 2) {
				continue
			}
			label := e.Name
			if label == "" {
				label = e.ID
			}
			en := Node{ID: "ext:" + e.ID, Kind: "extension", Label: label,
				Sub: fmt.Sprintf("%s, %d host(s)", e.Browser, extHosts[e.ID])}
			switch e.Level {
			case "high":
				en.Status, en.Detail = "critical", strings.Join(e.Reasons, "; ")
			case "medium":
				en.Status, en.Detail = "warning", strings.Join(e.Reasons, "; ")
			}
			b.node(en)
			b.edge(hostID, en.ID, "installs")
		}
	}

	// Rules attach to the groups they govern. Every host belongs to
	// exactly one group node (including the synthetic "(ungrouped)"
	// one), so a rule with no group scope reaches the whole fleet by
	// edging to all of them rather than to every host.
	groupIDs := make([]string, 0, 8)
	for id, n := range b.nodes {
		if n.Kind == "group" {
			groupIDs = append(groupIDs, id)
		}
	}
	sort.Strings(groupIDs)
	attach := func(ruleID, scope string) {
		if scope == "" {
			for _, gid := range groupIDs {
				b.edge(ruleID, gid, "governs")
			}
			return
		}
		b.edge(ruleID, "group:"+scope, "governs")
	}
	for _, r := range rules {
		sub := "policy rule"
		n := Node{ID: "rule:" + r.ID, Kind: "rule", Label: r.Name, Sub: sub}
		if r.AutoRemediate != "" {
			n.Sub = sub + ", auto-remediates"
			if r.RequireApproval {
				n.Sub = sub + ", needs approval"
			}
		}
		b.node(n)
		attach(n.ID, r.Group)
	}
	for _, r := range softwareRules {
		n := Node{ID: "srule:" + r.ID, Kind: "rule", Label: r.Name, Sub: "software " + r.Kind + " rule",
			Detail: "matches " + r.Match}
		b.node(n)
		attach(n.ID, r.Group)
	}

	return assemble(b, opts)
}

// licensedProducts returns the sprawl-catalog product names installed
// on this host -- the "we pay for this" reason a package is notable
// even when nothing is wrong with it.
func licensedProducts(in compliance.Input) []string {
	fact, ok := in.Facts["installed_software"]
	if !ok {
		return nil
	}
	var items []map[string]any
	switch t := fact.Data["items"].(type) {
	case []map[string]any:
		items = t
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				items = append(items, m)
			}
		}
	}
	hit := map[string]bool{}
	for _, m := range items {
		name, _ := m["name"].(string)
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			continue
		}
		for _, p := range sprawl.Catalog {
			if !p.Licensed {
				continue
			}
			for _, match := range p.Match {
				if strings.Contains(lower, strings.ToLower(match)) {
					hit[p.Name] = true
					break
				}
			}
		}
	}
	out := make([]string, 0, len(hit))
	for name := range hit {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// assemble applies the type filter, the focus narrowing and the node
// cap, then lays the result out.
func assemble(b *builder, opts Options) Graph {
	counts := map[string]int{}
	for _, n := range b.nodes {
		counts[n.Kind]++
	}

	keep := map[string]bool{}
	for id, n := range b.nodes {
		if len(opts.Types) == 0 || opts.Types[n.Kind] {
			keep[id] = true
		}
	}
	edges := filterEdges(b.edges, keep)
	if len(opts.Types) > 0 {
		contract(b, keep, edges)
	}

	if opts.Focus != "" && keep[opts.Focus] {
		depth := opts.Depth
		if depth <= 0 {
			depth = 1
		}
		keep = reachable(opts.Focus, edges, depth)
		edges = filterEdges(b.edges, keep)
	}

	degree := map[string]int{}
	for _, e := range edges {
		degree[e.From]++
		degree[e.To]++
	}

	max := opts.MaxNodes
	if max <= 0 {
		max = DefaultMaxNodes
	}
	omitted := 0
	if len(keep) > max {
		ordered := make([]string, 0, len(keep))
		for id := range keep {
			ordered = append(ordered, id)
		}
		// Drop the least connected of the most expendable kinds first;
		// hosts, groups and rules are the skeleton and stay.
		sort.Slice(ordered, func(i, j int) bool {
			pi, pj := dropPriority(b.nodes[ordered[i]].Kind), dropPriority(b.nodes[ordered[j]].Kind)
			if pi != pj {
				return pi < pj
			}
			if degree[ordered[i]] != degree[ordered[j]] {
				return degree[ordered[i]] > degree[ordered[j]]
			}
			return ordered[i] < ordered[j]
		})
		omitted = len(ordered) - max
		for _, id := range ordered[max:] {
			delete(keep, id)
		}
		edges = filterEdges(b.edges, keep)
		degree = map[string]int{}
		for _, e := range edges {
			degree[e.From]++
			degree[e.To]++
		}
	}

	ids := make([]string, 0, len(keep))
	for id := range keep {
		ids = append(ids, id)
	}
	// Stable order: by kind (legend order), then label, then id. This
	// is also what makes the layout deterministic -- initial positions
	// come from this order, so there is no seed to drift.
	kindRank := map[string]int{}
	for i, k := range Kinds {
		kindRank[k] = i
	}
	sort.Slice(ids, func(i, j int) bool {
		a, c := b.nodes[ids[i]], b.nodes[ids[j]]
		if kindRank[a.Kind] != kindRank[c.Kind] {
			return kindRank[a.Kind] < kindRank[c.Kind]
		}
		if a.Label != c.Label {
			return a.Label < c.Label
		}
		return a.ID < c.ID
	})

	g := Graph{Width: 1000, Height: 720, Nodes: make([]Node, 0, len(ids)), Edges: []Edge{},
		Counts: counts, Omitted: omitted, Focus: opts.Focus}
	for _, id := range ids {
		n := *b.nodes[id]
		n.Degree = degree[id]
		n.R = radius(n.Kind, n.Degree)
		if id == opts.Focus {
			// The entity the view is about should read as its subject,
			// not as one node among many.
			n.R = math.Round(n.R*1.55*10) / 10
		}
		g.Nodes = append(g.Nodes, n)
	}
	keys := make([]string, 0, len(edges))
	for k := range edges {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g.Edges = append(g.Edges, edges[k])
	}

	layout(&g)
	return g
}

// contract rescues relationships a type filter would otherwise hide.
// Asking for hosts and CVEs alone removes the package nodes that join
// them, which silently drops the very links the question was about, so
// for every removed node its surviving neighbors are joined directly
// by an "indirect" edge. The dashboard draws those dashed and the
// legend names them, because a contracted path is a derived fact, not
// a relationship the fleet actually reported.
//
// Two limits keep this from turning into a hairball. Only pairs from
// different families are joined, so a package shared by fifteen hosts
// does not become a hundred host-to-host edges (that is a real
// question, but a different one, and it belongs to an explicit
// host-and-package view). And a removed node with more surviving
// neighbors than maxContractDegree is skipped outright.
func contract(b *builder, keep map[string]bool, edges map[string]Edge) {
	const maxContractDegree = 24

	adj := map[string][]string{}
	for _, e := range b.edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	direct := map[string]bool{}
	for _, e := range edges {
		direct[e.From+"\x00"+e.To] = true
		direct[e.To+"\x00"+e.From] = true
	}

	removed := make([]string, 0, len(b.nodes))
	for id := range b.nodes {
		if !keep[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(removed)

	for _, mid := range removed {
		survivors := make([]string, 0, len(adj[mid]))
		seen := map[string]bool{}
		for _, nb := range adj[mid] {
			if keep[nb] && !seen[nb] {
				survivors = append(survivors, nb)
				seen[nb] = true
			}
		}
		if len(survivors) < 2 || len(survivors) > maxContractDegree {
			continue
		}
		sort.Strings(survivors)
		for i := 0; i < len(survivors); i++ {
			for j := i + 1; j < len(survivors); j++ {
				a, c := survivors[i], survivors[j]
				if b.nodes[a].Family == b.nodes[c].Family {
					continue
				}
				if direct[a+"\x00"+c] {
					continue
				}
				e := Edge{From: a, To: c, Kind: "indirect"}
				edges[a+"\x00"+c+"\x00indirect"] = e
				direct[a+"\x00"+c], direct[c+"\x00"+a] = true, true
			}
		}
	}
}

func filterEdges(all map[string]Edge, keep map[string]bool) map[string]Edge {
	out := make(map[string]Edge, len(all))
	for k, e := range all {
		if keep[e.From] && keep[e.To] {
			out[k] = e
		}
	}
	return out
}

// reachable returns every node within depth hops of start, treating
// edges as undirected.
func reachable(start string, edges map[string]Edge, depth int) map[string]bool {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	seen := map[string]bool{start: true}
	frontier := []string{start}
	for d := 0; d < depth; d++ {
		var next []string
		for _, id := range frontier {
			neighbors := append([]string(nil), adj[id]...)
			sort.Strings(neighbors)
			for _, nb := range neighbors {
				if !seen[nb] {
					seen[nb] = true
					next = append(next, nb)
				}
			}
		}
		frontier = next
	}
	return seen
}

// dropPriority orders kinds by how readily the node cap discards them:
// lower stays.
func dropPriority(kind string) int {
	switch kind {
	case "host", "group", "rule":
		return 0
	case "cve":
		return 1
	case "certificate", "extension":
		return 2
	default: // package
		return 3
	}
}

// radius sizes a node by how many things it touches, so the hubs read
// as hubs. Magnitude belongs on size here, not on color, which is
// already carrying family.
func radius(kind string, degree int) float64 {
	base := 9.0
	switch kind {
	case "group":
		base = 13
	case "host":
		base = 11
	}
	r := base + 1.6*math.Sqrt(float64(degree))
	if r > 26 {
		r = 26
	}
	return math.Round(r*10) / 10
}

// layout runs a fixed-iteration force-directed relaxation. No
// randomness: initial positions come from the caller's stable node
// order, so the same fleet lays out identically every time.
func layout(g *Graph) {
	n := len(g.Nodes)
	if n == 0 {
		return
	}
	if n == 1 {
		g.Nodes[0].X, g.Nodes[0].Y = float64(g.Width)/2, float64(g.Height)/2
		return
	}
	w, h := float64(g.Width), float64(g.Height)
	cx, cy := w/2, h/2

	// Seed on a spiral rather than a circle: a circle puts every node
	// the same distance from the center, which is a symmetric starting
	// point the relaxation takes far longer to break out of.
	for i := range g.Nodes {
		t := float64(i) / float64(n)
		angle := 2 * math.Pi * t * 6
		rad := 40 + 280*t
		g.Nodes[i].X = cx + rad*math.Cos(angle)
		g.Nodes[i].Y = cy + rad*math.Sin(angle)
	}

	index := make(map[string]int, n)
	for i, node := range g.Nodes {
		index[node.ID] = i
	}
	type link struct{ a, b int }
	links := make([]link, 0, len(g.Edges))
	for _, e := range g.Edges {
		a, okA := index[e.From]
		bIdx, okB := index[e.To]
		if okA && okB {
			links = append(links, link{a, bIdx})
		}
	}

	area := w * h
	k := math.Sqrt(area / float64(n))
	dispX := make([]float64, n)
	dispY := make([]float64, n)
	const iterations = 260
	temp := w / 8

	for iter := 0; iter < iterations; iter++ {
		for i := range dispX {
			dispX[i], dispY[i] = 0, 0
		}
		// repulsion, every pair
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				dx := g.Nodes[i].X - g.Nodes[j].X
				dy := g.Nodes[i].Y - g.Nodes[j].Y
				d2 := dx*dx + dy*dy
				if d2 < 0.01 {
					// Coincident nodes get nudged apart along a fixed
					// axis derived from their indices, keeping this
					// deterministic.
					dx, dy, d2 = float64(i-j)*0.01+0.01, float64(i+j)*0.001+0.01, 0.01
				}
				d := math.Sqrt(d2)
				force := k * k / d
				ux, uy := dx/d, dy/d
				dispX[i] += ux * force
				dispY[i] += uy * force
				dispX[j] -= ux * force
				dispY[j] -= uy * force
			}
		}
		// attraction along edges
		for _, l := range links {
			dx := g.Nodes[l.a].X - g.Nodes[l.b].X
			dy := g.Nodes[l.a].Y - g.Nodes[l.b].Y
			d := math.Sqrt(dx*dx + dy*dy)
			if d < 0.01 {
				continue
			}
			force := d * d / k
			ux, uy := dx/d, dy/d
			dispX[l.a] -= ux * force
			dispY[l.a] -= uy * force
			dispX[l.b] += ux * force
			dispY[l.b] += uy * force
		}
		// gentle pull to center so disconnected nodes do not fly off
		for i := 0; i < n; i++ {
			dispX[i] += (cx - g.Nodes[i].X) * 0.012
			dispY[i] += (cy - g.Nodes[i].Y) * 0.012
		}
		for i := 0; i < n; i++ {
			d := math.Sqrt(dispX[i]*dispX[i] + dispY[i]*dispY[i])
			if d < 0.01 {
				continue
			}
			step := math.Min(d, temp)
			g.Nodes[i].X += dispX[i] / d * step
			g.Nodes[i].Y += dispY[i] / d * step
		}
		temp *= 0.975
	}

	// Order matters: fit scales positions into the canvas, so it has to
	// run before the separation pass rather than after (scaling down
	// afterwards would put overlapping nodes back on top of each other).
	// Separation can then push a node past the edge, so clamp last.
	fit(g)
	separate(g)
	clamp(g)
	assignLabels(g)
}

// clamp keeps every node, and room for its label, inside the canvas.
func clamp(g *Graph) {
	for i := range g.Nodes {
		n := &g.Nodes[i]
		pad := n.R + 6
		n.X = math.Round(math.Max(pad, math.Min(float64(g.Width)-pad, n.X))*10) / 10
		n.Y = math.Round(math.Max(pad, math.Min(float64(g.Height)-pad-14, n.Y))*10) / 10
	}
}

// separate pushes overlapping nodes apart. The relaxation above treats
// nodes as points, so two entities with identical neighborhoods -- four
// fleet-wide rules all governing the same six groups, say -- settle on
// exactly the same coordinates and draw as one blob. This pass gives
// every node its own space, deterministically: pairs are visited in
// index order and pushed along the axis between them.
func separate(g *Graph) {
	n := len(g.Nodes)
	const passes = 140
	for pass := 0; pass < passes; pass++ {
		moved := false
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				a, b := &g.Nodes[i], &g.Nodes[j]
				minDist := a.R + b.R + 14
				dx, dy := b.X-a.X, b.Y-a.Y
				d := math.Sqrt(dx*dx + dy*dy)
				if d >= minDist {
					continue
				}
				if d < 0.001 {
					// Exactly coincident: separate along an axis derived
					// from the index pair so the result is repeatable.
					angle := 2 * math.Pi * float64(i*31+j*17) / float64(n*48+1)
					dx, dy, d = math.Cos(angle), math.Sin(angle), 1
				}
				push := (minDist - d) / 2
				ux, uy := dx/d, dy/d
				a.X -= ux * push
				a.Y -= uy * push
				b.X += ux * push
				b.Y += uy * push
				moved = true
			}
		}
		if !moved {
			break
		}
	}
}

// assignLabels decides which nodes carry a direct label, so the dense
// middle of a graph does not turn into overlapping text. Most-connected
// first, skipping any label whose estimated box would overlap one
// already placed. Widths are estimated (the server has no font
// metrics) against the dashboard's 10.5px label, which is close enough
// to keep text from colliding and errs toward fewer labels.
func assignLabels(g *Graph) {
	const (
		charWidth  = 5.6
		lineHeight = 13.0
		maxChars   = 24
	)
	order := make([]int, len(g.Nodes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := g.Nodes[order[a]], g.Nodes[order[b]]
		if x.Degree != y.Degree {
			return x.Degree > y.Degree
		}
		// Ties broken by kind importance then id, so the choice of which
		// label survives is stable run to run.
		if dropPriority(x.Kind) != dropPriority(y.Kind) {
			return dropPriority(x.Kind) < dropPriority(y.Kind)
		}
		return x.ID < y.ID
	})

	type box struct{ x0, y0, x1, y1 float64 }
	// Every node's own footprint is occupied space to begin with: a
	// label is no more readable sitting on top of a neighboring node
	// than on top of another label.
	placed := make([]box, 0, 2*len(g.Nodes))
	for _, n := range g.Nodes {
		placed = append(placed, box{n.X - n.R, n.Y - n.R, n.X + n.R, n.Y + n.R})
	}
	overlaps := func(b box) bool {
		for _, p := range placed {
			if b.x0 < p.x1 && p.x0 < b.x1 && b.y0 < p.y1 && p.y0 < b.y1 {
				return true
			}
		}
		return false
	}
	for _, i := range order {
		n := &g.Nodes[i]
		runes := len([]rune(n.Label))
		if runes > maxChars {
			runes = maxChars
		}
		half := float64(runes) * charWidth / 2
		// Below the node reads best, so try that first, then above,
		// then out to either side. Giving up on a label entirely is the
		// last resort -- the name is still in the tooltip and the table.
		candidates := []struct {
			anchor string
			b      box
		}{
			{"below", box{n.X - half, n.Y + n.R + 3, n.X + half, n.Y + n.R + 3 + lineHeight}},
			{"above", box{n.X - half, n.Y - n.R - 3 - lineHeight, n.X + half, n.Y - n.R - 3}},
			{"right", box{n.X + n.R + 4, n.Y - lineHeight/2, n.X + n.R + 4 + 2*half, n.Y + lineHeight/2}},
			{"left", box{n.X - n.R - 4 - 2*half, n.Y - lineHeight/2, n.X - n.R - 4, n.Y + lineHeight/2}},
		}
		for _, c := range candidates {
			if overlaps(c.b) {
				continue
			}
			if c.b.x0 < 0 || c.b.x1 > float64(g.Width) || c.b.y0 < 0 || c.b.y1 > float64(g.Height) {
				continue // a label running off the canvas is no label at all
			}
			placed = append(placed, c.b)
			n.ShowLabel = true
			n.LabelAnchor = c.anchor
			break
		}
	}
}

// fit rescales the relaxed positions to the canvas, leaving room for
// each node's radius and its label.
func fit(g *Graph) {
	minX, minY := math.Inf(1), math.Inf(1)
	maxX, maxY := math.Inf(-1), math.Inf(-1)
	for _, n := range g.Nodes {
		minX, maxX = math.Min(minX, n.X), math.Max(maxX, n.X)
		minY, maxY = math.Min(minY, n.Y), math.Max(maxY, n.Y)
	}
	const pad = 54.0
	spanX, spanY := maxX-minX, maxY-minY
	if spanX < 1 {
		spanX = 1
	}
	if spanY < 1 {
		spanY = 1
	}
	scale := math.Min((float64(g.Width)-2*pad)/spanX, (float64(g.Height)-2*pad)/spanY)
	// Never magnify a small graph to fill the canvas; a handful of
	// nodes blown up to 1000px apart looks broken.
	if scale > 1 {
		scale = 1
	}
	offX := (float64(g.Width) - spanX*scale) / 2
	offY := (float64(g.Height) - spanY*scale) / 2
	for i := range g.Nodes {
		g.Nodes[i].X = math.Round(((g.Nodes[i].X-minX)*scale+offX)*10) / 10
		g.Nodes[i].Y = math.Round(((g.Nodes[i].Y-minY)*scale+offY)*10) / 10
	}
}

// Neighbors returns every edge touching id, with the node on the other
// end, for a detail pane's "what is this connected to" list. Edges come
// back grouped by kind in EdgeKinds order, then by the other node's
// label.
func (g Graph) Neighbors(id string) []Relation {
	byID := make(map[string]Node, len(g.Nodes))
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	var out []Relation
	for _, e := range g.Edges {
		switch id {
		case e.From:
			if other, ok := byID[e.To]; ok {
				out = append(out, Relation{Kind: e.Kind, Direction: "out", Other: other})
			}
		case e.To:
			if other, ok := byID[e.From]; ok {
				out = append(out, Relation{Kind: e.Kind, Direction: "in", Other: other})
			}
		}
	}
	rank := map[string]int{}
	for i, k := range EdgeKinds {
		rank[k] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].Other.Label < out[j].Other.Label
	})
	return out
}

// Relation is one edge as seen from a particular node.
type Relation struct {
	Kind      string `json:"kind"`
	Direction string `json:"direction"` // "out" or "in", relative to the node asked about
	Other     Node   `json:"other"`
}
