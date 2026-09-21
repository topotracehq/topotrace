/*******************************************************************************
 * @file         main.go
 * @brief        Command erd generates Muster's data-model documentation from the Go types themselves: docs/data-model.md (entity tables plus the relationships between them) and docs/data-model.svg (the entity relationship diagram the README shows).
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command erd generates Muster's data-model documentation from the Go
// types themselves: docs/data-model.md (entity tables plus the
// relationships between them) and docs/data-model.svg (the entity
// relationship diagram the README shows).
//
// The point of generating it is that a hand-drawn ERD is wrong within a
// month. Entities and their fields come from parsing
// internal/model/types.go, so they cannot drift from the code.
//
// Relationships are the one part that cannot be read off the structs --
// Go has no foreign keys, and Muster deliberately does not carry ORM
// tags -- so they are declared in the relationships table below. To
// stop those from silently going stale, every declared relationship is
// checked against the parsed types: naming a struct or a field that no
// longer exists is a hard error, not a quietly wrong diagram. Same for
// the Document kinds, each of which is verified to still be declared
// somewhere in internal/.
//
// Usage:
//
//	go run ./tools/erd           # write docs/data-model.{md,svg}
//	go run ./tools/erd -check    # fail if either file is out of date
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// entity is one parsed struct from internal/model.
type entity struct {
	Name   string
	Doc    string
	Fields []field
}

type field struct {
	Name string
	Type string
	JSON string
	Doc  string
}

// relation is one declared relationship between two entities.
// Maintained by hand (see the package comment) but validated against
// the parsed structs, so it cannot name something that no longer
// exists.
type relation struct {
	From      string // entity name
	FromField string // the field that carries the reference
	To        string // entity name
	ToField   string // the field it refers to
	Card      string // cardinality, as "many-to-one" or "one-to-one"
	Note      string
}

var relations = []relation{
	{"Fact", "Host", "Host", "Name", "many-to-one",
		"One row per (host, category). A host's current facts; history lives in Change."},
	{"Change", "Host", "Host", "Name", "many-to-one",
		"One row per observed field-level change, written by the cook pipeline on every report."},
	{"Action", "Host", "Host", "Name", "many-to-one",
		"Queued remediation work. The agent claims actions for its own host only."},
	{"AuditEntry", "Target", "Host", "Name", "many-to-one",
		"Soft reference: Target is a host name for host-scoped events, and something else (a rule id, a format name) otherwise."},
	{"Enrollment", "Host", "Host", "Name", "one-to-one",
		"A single-host, revocable credential used only to self-register. The host row may not exist yet when the enrollment does."},
	{"Rule", "Group", "Host", "Group", "many-to-many",
		"Scope, not ownership: a rule with an empty Group applies to every host, otherwise to hosts in that group."},
	{"SoftwareRule", "Group", "Host", "Group", "many-to-many",
		"Same scoping as Rule."},
	{"APIKey", "Group", "Host", "Group", "many-to-many",
		"A key with a Group can only read and act on hosts in that group."},
	{"DiscoveredAsset", "Address", "Host", "Name", "many-to-one",
		"Soft reference: a swept address that may turn out to be an enrolled host (Known), or may be something nobody manages."},
	{"Document", "ID", "Host", "Name", "many-to-one",
		"Soft reference, and only for some kinds: score_history, baseline and agent_health key their documents by host name, while alert_state and notify_queue use a fixed key. See the document-kind table."},
}

// documentKind is one (kind, id) convention stored in the Document
// table, with the package that owns it.
type documentKind struct {
	Kind    string
	Package string
	ID      string
	Purpose string
}

var documentKinds = []documentKind{
	{"score_history", "internal/history", "host name", "Posture, compliance, vulnerability count and staleness over time, one point per evaluator run."},
	{"baseline", "internal/baseline", "host name", "A captured golden set of a host's facts, to diff current state against."},
	{"alert_state", "internal/alerts", "fixed key", "Open violations with their first-seen, occurrence count and snooze window, so the evaluator can dedup instead of re-alerting."},
	{"approval", "internal/alerts", "rule id and host", "A remediation the evaluator proposed and parked, waiting for an operator to approve or reject."},
	{"notify_queue", "internal/webhook", "fixed key", "The durable outbound delivery queue: pending notifications with attempts and next-attempt time, plus dead letters."},
	{"bookmark", "internal/bookmark", "bookmark name", "A named snapshot of every host's headline numbers, for diffing \"what changed since last time\"."},
	{"agent_health", "internal/agenthealth", "host name", "Last check-in, reporting path and recent failures for each host's collector."},
}

func main() {
	check := flag.Bool("check", false, "fail if the generated files are out of date instead of writing them")
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	entities, err := parseModel(filepath.Join(*root, "internal", "model", "types.go"))
	if err != nil {
		fatal(err)
	}
	if len(entities) == 0 {
		fatal(fmt.Errorf("erd: parsed no entities out of internal/model/types.go"))
	}
	if err := validate(entities, *root); err != nil {
		fatal(err)
	}

	files := map[string][]byte{
		filepath.Join(*root, "docs", "data-model.md"):  renderMarkdown(entities),
		filepath.Join(*root, "docs", "data-model.svg"): renderSVG(entities),
	}
	stale := 0
	for path, want := range files {
		got, err := os.ReadFile(path)
		if err == nil && bytes.Equal(got, want) {
			continue
		}
		if *check {
			fmt.Printf("out of date: %s\n", path)
			stale++
			continue
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s\n", path)
	}
	if *check && stale > 0 {
		fmt.Fprintf(os.Stderr, "\n%d generated file(s) out of date -- run: go run ./tools/erd\n", stale)
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// parseModel reads every exported struct out of the model package, in
// source order (which is the order a reader of the file would meet
// them, and more useful than alphabetical).
func parseModel(path string) ([]entity, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("erd: parsing %s: %w", path, err)
	}
	var out []entity
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			e := entity{Name: ts.Name.Name, Doc: firstSentence(docText(ts.Doc, gen.Doc))}
			for _, f := range st.Fields.List {
				typeName := exprString(f.Type)
				jsonName := jsonTag(f.Tag)
				doc := firstSentence(docText(f.Doc, nil))
				if len(f.Names) == 0 { // embedded
					e.Fields = append(e.Fields, field{Name: typeName, Type: typeName, JSON: jsonName, Doc: doc})
					continue
				}
				for _, n := range f.Names {
					if !n.IsExported() {
						continue
					}
					e.Fields = append(e.Fields, field{Name: n.Name, Type: typeName, JSON: jsonName, Doc: doc})
				}
			}
			if len(e.Fields) > 0 {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func docText(groups ...*ast.CommentGroup) string {
	for _, g := range groups {
		if g != nil && strings.TrimSpace(g.Text()) != "" {
			return g.Text()
		}
	}
	return ""
}

// firstSentence collapses a doc comment to its first sentence, so the
// tables stay readable; the code itself remains the full explanation.
func firstSentence(doc string) string {
	doc = strings.Join(strings.Fields(strings.ReplaceAll(doc, "\n", " ")), " ")
	if doc == "" {
		return ""
	}
	// Stop at the first ". " that is not inside an abbreviation-ish
	// token; good enough for prose written in this repo's style.
	for i := 0; i < len(doc)-1; i++ {
		if doc[i] == '.' && doc[i+1] == ' ' {
			return doc[:i+1]
		}
	}
	return doc
}

func jsonTag(tag *ast.BasicLit) string {
	if tag == nil {
		return ""
	}
	raw, err := strconv.Unquote(tag.Value)
	if err != nil {
		return ""
	}
	i := strings.Index(raw, `json:"`)
	if i < 0 {
		return ""
	}
	rest := raw[i+len(`json:"`):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return strings.SplitN(rest[:j], ",", 2)[0]
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.ArrayType:
		return "[]" + exprString(t.Elt)
	case *ast.MapType:
		return "map[" + exprString(t.Key) + "]" + exprString(t.Value)
	case *ast.InterfaceType:
		return "any"
	default:
		return "?"
	}
}

// validate is what keeps the hand-declared parts honest: every relation
// and every document kind has to still correspond to something real.
func validate(entities []entity, root string) error {
	byName := map[string]map[string]bool{}
	for _, e := range entities {
		byName[e.Name] = map[string]bool{}
		for _, f := range e.Fields {
			byName[e.Name][f.Name] = true
		}
	}
	for _, r := range relations {
		for _, pair := range [][2]string{{r.From, r.FromField}, {r.To, r.ToField}} {
			fields, ok := byName[pair[0]]
			if !ok {
				return fmt.Errorf("erd: relation names entity %q, which no longer exists in internal/model", pair[0])
			}
			if !fields[pair[1]] {
				return fmt.Errorf("erd: relation names %s.%s, which no longer exists", pair[0], pair[1])
			}
		}
	}
	// Each document kind should still be declared somewhere under its
	// owning package.
	for _, dk := range documentKinds {
		found, err := grepDir(filepath.Join(root, dk.Package), `"`+dk.Kind+`"`)
		if err != nil {
			return fmt.Errorf("erd: checking document kind %q: %w", dk.Kind, err)
		}
		if !found {
			return fmt.Errorf("erd: document kind %q is not declared anywhere in %s", dk.Kind, dk.Package)
		}
	}
	return nil
}

func grepDir(dir, needle string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return false, err
		}
		if bytes.Contains(body, []byte(needle)) {
			return true, nil
		}
	}
	return false, nil
}

// generatedBanner is plain prose rather than an HTML comment because
// the dashboard's Docs tab renders a small markdown subset and would
// show a comment as literal text.
const generatedBanner = "*Generated by `tools/erd` from `internal/model/types.go`. Do not edit by hand; run `go run ./tools/erd` instead.*"

func renderMarkdown(entities []entity) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Data model\n\n%s\n\n", generatedBanner)
	b.WriteString(`Muster's persisted shapes, generated from ` + "`internal/model/types.go`" + ` so
this page cannot drift from the code. Every entity below is stored
through the ` + "`store.Store`" + ` interface, which has two
implementations: an in-memory one for demos and tests
(` + "`internal/store/memstore`" + `) and Postgres
(` + "`internal/store/pgstore`" + `, schema managed by the numbered
migrations in that package).

There are no foreign keys. Muster carries no ORM, and the store
interface is deliberately a set of explicit methods rather than a query
builder, so the relationships in the next section are enforced by the
code that writes rows, not by the database. They are documented here
and checked by the generator against the real field names.

For the live version of this picture -- the actual hosts, packages,
vulnerabilities and rules in a running fleet, and how they connect --
see the Entity map tab and ` + "`docs/entity-graph.md`" + `.

`)

	b.WriteString("## Entities\n\n")
	for _, e := range entities {
		fmt.Fprintf(&b, "### %s\n\n", e.Name)
		if e.Doc != "" {
			fmt.Fprintf(&b, "%s\n\n", e.Doc)
		}
		b.WriteString("| Field | Type | JSON | Notes |\n| --- | --- | --- | --- |\n")
		for _, f := range e.Fields {
			jsonName := f.JSON
			if jsonName == "" {
				jsonName = "-"
			}
			note := f.Doc
			if note == "" {
				note = ""
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n", f.Name, f.Type, jsonName, note)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Relationships\n\n")
	b.WriteString("| From | To | Cardinality | Meaning |\n| --- | --- | --- | --- |\n")
	for _, r := range relations {
		fmt.Fprintf(&b, "| `%s.%s` | `%s.%s` | %s | %s |\n", r.From, r.FromField, r.To, r.ToField, r.Card, r.Note)
	}
	b.WriteString(`
` + "`Host.Name`" + ` is the join key for almost everything: it is the
primary key a host is known by, the value an agent authenticates as,
and the reference every per-host record carries. Board groups are not
their own entity -- a group is just a string on ` + "`Host.Group`" + `,
which is why rule and key scoping is a many-to-many over that string
rather than a join table.

`)

	b.WriteString("## Document kinds\n\n")
	b.WriteString(`` + "`Document`" + ` is a generic ` + "`(kind, id) -> JSON`" + ` record, added
so features that need to persist a little state do not each need their
own table and migration. Everything below shares that one table.

| Kind | Owner | ID is | What it holds |
| --- | --- | --- | --- |
`)
	for _, dk := range documentKinds {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", dk.Kind, dk.Package, dk.ID, dk.Purpose)
	}
	b.WriteString(`
The tradeoff is deliberate: these records are read and written whole,
by exactly one package each, and are never queried across. Anything
that needed indexing or cross-record queries would earn a real table
instead.
`)
	return []byte(b.String())
}

// renderSVG draws the entity relationship diagram: a box per entity
// with its key fields, and a line per relationship. Laid out on a
// fixed grid rather than by any physics, so the file is stable between
// runs and the diff on regeneration is empty unless the model actually
// changed.
func renderSVG(entities []entity) []byte {
	// Host sits in the middle column since nearly everything joins to
	// it; the rest are placed around it in a stable order.
	const (
		boxW    = 196.0
		rowH    = 15.0
		headH   = 26.0
		colGap  = 74.0
		rowGap  = 30.0
		padding = 26.0
		maxRows = 7
	)
	type placed struct {
		e          entity
		x, y, w, h float64
		fields     []field
	}

	// Which fields to show: the ones that carry identity or a
	// relationship, plus enough of the rest to make the box informative.
	keyish := map[string]bool{"Name": true, "ID": true, "Host": true, "Group": true, "Kind": true,
		"Category": true, "Address": true, "Target": true, "Actor": true}
	pick := func(e entity) []field {
		var out, rest []field
		for _, f := range e.Fields {
			if keyish[f.Name] {
				out = append(out, f)
			} else {
				rest = append(rest, f)
			}
		}
		for _, f := range rest {
			if len(out) >= maxRows {
				break
			}
			out = append(out, f)
		}
		return out
	}

	order := make([]entity, 0, len(entities))
	var host entity
	for _, e := range entities {
		if e.Name == "Host" {
			host = e
			continue
		}
		order = append(order, e)
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].Name < order[j].Name })

	// Three columns: left, the Host column, right. Split the rest evenly.
	left := make([]entity, 0, len(order))
	right := make([]entity, 0, len(order))
	for i, e := range order {
		if i%2 == 0 {
			left = append(left, e)
		} else {
			right = append(right, e)
		}
	}

	boxes := map[string]*placed{}
	var all []*placed
	column := func(list []entity, x float64) float64 {
		y := padding
		for _, e := range list {
			fs := pick(e)
			h := headH + float64(len(fs))*rowH + 8
			p := &placed{e: e, x: x, y: y, w: boxW, h: h, fields: fs}
			boxes[e.Name] = p
			all = append(all, p)
			y += h + rowGap
		}
		return y
	}
	leftBottom := column(left, padding)
	rightBottom := column(right, padding+2*(boxW+colGap))

	// Host goes in the middle column, vertically centered against the
	// taller of the two side columns.
	hostFields := pick(host)
	hostH := headH + float64(len(hostFields))*rowH + 8
	tallest := leftBottom
	if rightBottom > tallest {
		tallest = rightBottom
	}
	hp := &placed{e: host, x: padding + boxW + colGap, y: (tallest - rowGap - hostH) / 2, w: boxW, h: hostH, fields: hostFields}
	boxes[host.Name] = hp
	all = append(all, hp)

	width := padding*2 + 3*boxW + 2*colGap
	height := tallest - rowGap + padding + 18

	esc := func(s string) string {
		s = strings.ReplaceAll(s, "&", "&amp;")
		s = strings.ReplaceAll(s, "<", "&lt;")
		return strings.ReplaceAll(s, ">", "&gt;")
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" font-family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif">`+"\n", width, height, width, height)
	b.WriteString(`<!-- Generated by tools/erd. Do not edit by hand; run: go run ./tools/erd -->` + "\n")
	fmt.Fprintf(&b, `<rect width="%.0f" height="%.0f" fill="#f4f3ef"/>`+"\n", width, height)
	b.WriteString(`<style>
.ent-box { fill: #ffffff; stroke: #e4e1d8; stroke-width: 1.5; }
.ent-head { fill: #1a2123; }
.ent-head-text { fill: #ffffff; font-size: 12px; font-weight: 700; }
.ent-field { fill: #23272a; font-size: 10.5px; }
.ent-key { fill: #23272a; font-size: 10.5px; font-weight: 700; }
.ent-type { fill: #6b7278; font-size: 9.5px; }
.rel { stroke: #9aa3a8; stroke-width: 1.4; fill: none; }
.rel-many { stroke-dasharray: 4 3; }
.rel-label { fill: #6b7278; font-size: 9px; }
</style>
`)

	// Relationship lines first, so boxes draw over their ends.
	for _, r := range relations {
		from, to := boxes[r.From], boxes[r.To]
		if from == nil || to == nil {
			continue
		}
		fx, fy := from.x+from.w/2, from.y+from.h/2
		tx, ty := to.x+to.w/2, to.y+to.h/2
		// Leave from the side facing the target.
		if fx < tx {
			fx, tx = from.x+from.w, to.x
		} else {
			fx, tx = from.x, to.x+to.w
		}
		midX := (fx + tx) / 2
		cls := "rel"
		if strings.HasPrefix(r.Card, "many") {
			cls += " rel-many"
		}
		fmt.Fprintf(&b, `<path class="%s" d="M %.1f %.1f C %.1f %.1f, %.1f %.1f, %.1f %.1f"/>`+"\n",
			cls, fx, fy, midX, fy, midX, ty, tx, ty)
	}

	// Legend: the line style is the only thing on the diagram that is
	// not self-explanatory.
	ly := height - padding + 4
	fmt.Fprintf(&b, `<path class="rel" d="M %.1f %.1f h 26"/>`+"\n", padding, ly-4)
	fmt.Fprintf(&b, `<text class="rel-label" x="%.1f" y="%.1f">one-to-one</text>`+"\n", padding+31, ly-1)
	fmt.Fprintf(&b, `<path class="rel rel-many" d="M %.1f %.1f h 26"/>`+"\n", padding+100, ly-4)
	fmt.Fprintf(&b, `<text class="rel-label" x="%.1f" y="%.1f">many-to-one or many-to-many (see docs/data-model.md for each)</text>`+"\n", padding+131, ly-1)

	for _, p := range all {
		fmt.Fprintf(&b, `<g><rect class="ent-box" x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="7"/>`+"\n", p.x, p.y, p.w, p.h)
		fmt.Fprintf(&b, `<path class="ent-head" d="M %.1f %.1f h %.1f a 7 7 0 0 1 7 7 v %.1f h -%.1f v -%.1f a 7 7 0 0 1 7 -7 z"/>`+"\n",
			p.x+7, p.y, p.w-14, headH-7, p.w, headH-7)
		fmt.Fprintf(&b, `<text class="ent-head-text" x="%.1f" y="%.1f">%s</text>`+"\n", p.x+10, p.y+17.5, esc(p.e.Name))
		for i, f := range p.fields {
			y := p.y + headH + 11 + float64(i)*rowH
			cls := "ent-field"
			if keyish[f.Name] {
				cls = "ent-key"
			}
			fmt.Fprintf(&b, `<text class="%s" x="%.1f" y="%.1f">%s</text>`+"\n", cls, p.x+10, y, esc(f.Name))
			fmt.Fprintf(&b, `<text class="ent-type" x="%.1f" y="%.1f" text-anchor="end">%s</text>`+"\n", p.x+p.w-10, y, esc(f.Type))
		}
		if len(p.e.Fields) > len(p.fields) {
			y := p.y + headH + 11 + float64(len(p.fields))*rowH
			fmt.Fprintf(&b, `<text class="ent-type" x="%.1f" y="%.1f">+%d more</text>`+"\n", p.x+10, y, len(p.e.Fields)-len(p.fields))
		}
		b.WriteString("</g>\n")
	}
	b.WriteString("</svg>\n")
	return []byte(b.String())
}
