/*******************************************************************************
 * @file         baseline.go
 * @brief        Package baseline is config-drift detection: an operator captures a host's current facts as its "golden" baseline, and from then on TopoTrace can say exactly how the host has drifted from that known-good state -- packages added or removed, s...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package baseline is config-drift detection: an operator captures a
// host's current facts as its "golden" baseline, and from then on TopoTrace
// can say exactly how the host has drifted from that known-good state
// -- packages added or removed, services started, ports opened, users
// created, firewall flipped -- distinct from policy/compliance checks
// (which judge a host against rules) and from change history (which
// records every diff since the last report, not distance from an
// approved state).
//
// One model.Document per host (Kind "baseline") holding the captured
// facts. Drift is computed on read, never stored, so it's always
// against the host's current facts.
package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"topotrace/internal/model"
	"topotrace/internal/store"
)

// Kind is the model.Document kind this package owns.
const Kind = "baseline"

// Baseline is one host's captured golden state.
type Baseline struct {
	Host       string                    `json:"host"`
	CapturedAt time.Time                 `json:"captured_at"`
	CapturedBy string                    `json:"captured_by"`
	Note       string                    `json:"note,omitempty"`
	Facts      map[string]map[string]any `json:"facts"` // category -> data
}

// Drift is one difference between the baseline and the host now.
type Drift struct {
	Category string `json:"category"`
	Field    string `json:"field"`
	Action   string `json:"action"` // "add", "remove", "update"
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// Report is a baseline compared against current facts.
type Report struct {
	Host        string         `json:"host"`
	HasBaseline bool           `json:"has_baseline"`
	CapturedAt  time.Time      `json:"captured_at,omitempty"`
	CapturedBy  string         `json:"captured_by,omitempty"`
	Note        string         `json:"note,omitempty"`
	Categories  []string       `json:"categories,omitempty"`
	Drifted     bool           `json:"drifted"`
	Drift       []Drift        `json:"drift"`
	ByCategory  map[string]int `json:"by_category"`
}

// Capture stores facts as host's baseline. categories, if non-empty,
// limits which categories are captured; otherwise every reported one is.
func Capture(ctx context.Context, st store.Store, host, actor, note string, categories []string) (Baseline, error) {
	facts, err := st.ListFacts(ctx, host)
	if err != nil {
		return Baseline{}, err
	}
	want := map[string]bool{}
	for _, c := range categories {
		want[c] = true
	}
	b := Baseline{Host: host, CapturedAt: time.Now().UTC(), CapturedBy: actor, Note: note, Facts: map[string]map[string]any{}}
	for _, f := range facts {
		if len(want) > 0 && !want[f.Category] {
			continue
		}
		b.Facts[f.Category] = f.Data
	}
	if len(b.Facts) == 0 {
		return Baseline{}, fmt.Errorf("baseline: host %q has no facts to capture", host)
	}
	data, err := json.Marshal(b)
	if err != nil {
		return Baseline{}, err
	}
	if err := st.PutDocument(ctx, model.Document{Kind: Kind, ID: host, Data: data}); err != nil {
		return Baseline{}, err
	}
	return b, nil
}

// Get loads host's baseline, if any.
func Get(ctx context.Context, st store.Store, host string) (Baseline, bool, error) {
	doc, ok, err := st.GetDocument(ctx, Kind, host)
	if err != nil || !ok {
		return Baseline{}, false, err
	}
	var b Baseline
	if err := json.Unmarshal(doc.Data, &b); err != nil {
		return Baseline{}, false, err
	}
	b.Host = host
	return b, true, nil
}

// Delete removes host's baseline.
func Delete(ctx context.Context, st store.Store, host string) error {
	return st.DeleteDocument(ctx, Kind, host)
}

// Compare produces host's drift report against its current facts.
func Compare(ctx context.Context, st store.Store, host string) (Report, error) {
	rep := Report{Host: host, Drift: []Drift{}, ByCategory: map[string]int{}}
	b, ok, err := Get(ctx, st, host)
	if err != nil || !ok {
		return rep, err
	}
	rep.HasBaseline, rep.CapturedAt, rep.CapturedBy, rep.Note = true, b.CapturedAt, b.CapturedBy, b.Note
	facts, err := st.ListFacts(ctx, host)
	if err != nil {
		return rep, err
	}
	current := map[string]map[string]any{}
	for _, f := range facts {
		current[f.Category] = f.Data
	}
	cats := make([]string, 0, len(b.Facts))
	for c := range b.Facts {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	rep.Categories = cats
	for _, c := range cats {
		now, present := current[c]
		if !present {
			rep.Drift = append(rep.Drift, Drift{Category: c, Field: "(category)", Action: "remove", OldValue: "reported at capture", NewValue: "no longer reported"})
			rep.ByCategory[c]++
			continue
		}
		for _, d := range DiffData(c, b.Facts[c], now) {
			rep.Drift = append(rep.Drift, d)
			rep.ByCategory[c]++
		}
	}
	rep.Drifted = len(rep.Drift) > 0
	return rep, nil
}

// All returns a drift report for every host that has a baseline.
func All(ctx context.Context, st store.Store) ([]Report, error) {
	docs, err := st.ListDocuments(ctx, Kind)
	if err != nil {
		return nil, err
	}
	out := make([]Report, 0, len(docs))
	for _, d := range docs {
		rep, err := Compare(ctx, st, d.ID)
		if err != nil {
			continue
		}
		out = append(out, rep)
	}
	return out, nil
}

// DiffData compares one category's data. List-shaped categories
// ({"count", "items": [...]}) are diffed item-by-item, keyed by the
// item's natural identity (name, then id, then the first of a few
// well-known key fields), so "nginx was added" comes out as one line
// instead of the whole items array stringified. Everything else goes
// through store.Diff, the same field-level walk change history uses.
func DiffData(category string, oldData, newData map[string]any) []Drift {
	var out []Drift
	oldItems, oldIsList := oldData["items"]
	newItems, newIsList := newData["items"]
	if oldIsList || newIsList {
		oldByKey := indexItems(oldItems)
		newByKey := indexItems(newItems)
		keys := map[string]bool{}
		for k := range oldByKey {
			keys[k] = true
		}
		for k := range newByKey {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			o, hadOld := oldByKey[k]
			n, hasNew := newByKey[k]
			switch {
			case hadOld && !hasNew:
				out = append(out, Drift{Category: category, Field: k, Action: "remove", OldValue: summarize(o)})
			case !hadOld && hasNew:
				out = append(out, Drift{Category: category, Field: k, Action: "add", NewValue: summarize(n)})
			default:
				for _, ch := range store.Diff("", category, o, n) {
					out = append(out, Drift{Category: category, Field: k + "." + ch.Field, Action: ch.Action, OldValue: ch.OldValue, NewValue: ch.NewValue})
				}
			}
		}
		// then the non-item fields, excluding count (implied by items)
		rest := func(m map[string]any) map[string]any {
			r := map[string]any{}
			for k, v := range m {
				if k != "items" && k != "count" {
					r[k] = v
				}
			}
			return r
		}
		for _, ch := range store.Diff("", category, rest(oldData), rest(newData)) {
			out = append(out, Drift{Category: category, Field: ch.Field, Action: ch.Action, OldValue: ch.OldValue, NewValue: ch.NewValue})
		}
		return out
	}
	for _, ch := range store.Diff("", category, oldData, newData) {
		out = append(out, Drift{Category: category, Field: ch.Field, Action: ch.Action, OldValue: ch.OldValue, NewValue: ch.NewValue})
	}
	return out
}

var identityKeys = []string{"name", "id", "unit", "device", "filesystem", "mount", "port", "local_port", "user", "username", "interface", "address", "task", "profile", "hotfix_id"}

func indexItems(v any) map[string]map[string]any {
	out := map[string]map[string]any{}
	var list []map[string]any
	switch t := v.(type) {
	case []map[string]any:
		list = t
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				list = append(list, m)
			}
		}
	}
	for i, m := range list {
		key := ""
		for _, k := range identityKeys {
			if s, ok := m[k]; ok {
				key = fmt.Sprintf("%v", s)
				break
			}
		}
		if key == "" {
			raw, _ := json.Marshal(m)
			key = string(raw)
		}
		if _, dup := out[key]; dup {
			key = fmt.Sprintf("%s#%d", key, i)
		}
		out[key] = m
	}
	return out
}

func summarize(m map[string]any) string {
	if v, ok := m["version"]; ok {
		return fmt.Sprintf("%v", v)
	}
	raw, _ := json.Marshal(m)
	if len(raw) > 80 {
		return string(raw[:77]) + "..."
	}
	return string(raw)
}
