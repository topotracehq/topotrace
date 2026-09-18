/*******************************************************************************
 * @file         bookmark.go
 * @brief        Package bookmark is "what's changed since I last showed this?" -- a named snapshot of the fleet's headline state (every host's scores, the rule and asset counts) that a later request diffs against the live fleet.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package bookmark is "what's changed since I last showed this?" -- a
// named snapshot of the fleet's headline state (every host's scores,
// the rule and asset counts) that a later request diffs against the
// live fleet. Built for the person who gives the same demo to a repeat
// audience and wants to open with "here's what's new since last time"
// without hunting through the audit trail, but equally the person who
// wants to know what a week of patching actually changed.
//
// One model.Document per bookmark (Kind "bookmark"); the diff is
// computed on read against the current signals.
package bookmark

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"muster/internal/compliance"
	"muster/internal/model"
	"muster/internal/risk"
	"muster/internal/store"
)

// Kind is the model.Document kind this package owns.
const Kind = "bookmark"

// HostState is one host's headline numbers at bookmark time.
type HostState struct {
	Posture    int      `json:"posture"`
	Compliance int      `json:"compliance"`
	Risk       int      `json:"risk"`
	Vulns      int      `json:"vulns"`
	ShadowAI   int      `json:"shadow_ai"`
	Stale      bool     `json:"stale"`
	Group      string   `json:"group"`
	Tags       []string `json:"tags"`
}

// Bookmark is one saved snapshot.
type Bookmark struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	CreatedAt  time.Time            `json:"created_at"`
	CreatedBy  string               `json:"created_by"`
	Hosts      map[string]HostState `json:"hosts"`
	Rules      int                  `json:"rules"`
	Assets     int                  `json:"assets"`
	AvgPosture int                  `json:"avg_posture"`
	AvgRisk    int                  `json:"avg_risk"`
}

// Snapshot builds the current state from inputs.
func Snapshot(inputs []compliance.Input, rules, assets int) Bookmark {
	b := Bookmark{Hosts: map[string]HostState{}, Rules: rules, Assets: assets}
	sumP, sumR := 0, 0
	for _, in := range inputs {
		r := risk.Compute(in)
		c := compliance.Baseline.Evaluate(in)
		b.Hosts[in.Host.Name] = HostState{Posture: in.Posture.Score, Compliance: c.Score, Risk: r.Score, Vulns: len(in.VulnFindings),
			ShadowAI: len(in.ShadowAIViolations), Stale: in.Stale, Group: in.Host.Group, Tags: in.Host.Tags}
		sumP += in.Posture.Score
		sumR += r.Score
	}
	if n := len(inputs); n > 0 {
		b.AvgPosture, b.AvgRisk = sumP/n, sumR/n
	}
	return b
}

// Save stores a snapshot under a new ID.
func Save(ctx context.Context, st store.Store, b Bookmark, name, actor string) (Bookmark, error) {
	existing, err := st.ListDocuments(ctx, Kind)
	if err != nil {
		return Bookmark{}, err
	}
	maxID := 0
	for _, d := range existing {
		if n, err := strconv.Atoi(d.ID); err == nil && n > maxID {
			maxID = n
		}
	}
	b.ID = strconv.Itoa(maxID + 1)
	b.Name, b.CreatedBy, b.CreatedAt = name, actor, time.Now().UTC()
	if b.Name == "" {
		b.Name = "Bookmark " + b.CreatedAt.Format("Jan 2 15:04")
	}
	data, err := json.Marshal(b)
	if err != nil {
		return Bookmark{}, err
	}
	return b, st.PutDocument(ctx, model.Document{Kind: Kind, ID: b.ID, Data: data})
}

// List returns every bookmark, newest first.
func List(ctx context.Context, st store.Store) ([]Bookmark, error) {
	docs, err := st.ListDocuments(ctx, Kind)
	if err != nil {
		return nil, err
	}
	out := make([]Bookmark, 0, len(docs))
	for _, d := range docs {
		var b Bookmark
		if json.Unmarshal(d.Data, &b) == nil {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Get loads one bookmark.
func Get(ctx context.Context, st store.Store, id string) (Bookmark, bool, error) {
	doc, ok, err := st.GetDocument(ctx, Kind, id)
	if err != nil || !ok {
		return Bookmark{}, false, err
	}
	var b Bookmark
	return b, true, json.Unmarshal(doc.Data, &b)
}

// Delete removes one bookmark.
func Delete(ctx context.Context, st store.Store, id string) error {
	return st.DeleteDocument(ctx, Kind, id)
}

// Change is one line of a diff.
type Change struct {
	Host   string `json:"host,omitempty"`
	Kind   string `json:"kind"` // "host-added", "host-removed", "posture", "compliance", "risk", "vulns", "stale", "recovered", "group", "shadow-ai"
	Detail string `json:"detail"`
	Better bool   `json:"better"`
	Worse  bool   `json:"worse"`
}

// Diff is a bookmark compared to the fleet now.
type Diff struct {
	Bookmark  Bookmark `json:"bookmark"`
	Now       Bookmark `json:"now"`
	Changes   []Change `json:"changes"`
	Better    int      `json:"better"`
	Worse     int      `json:"worse"`
	Unchanged int      `json:"unchanged_hosts"`
	Summary   string   `json:"summary"`
}

// Compare diffs then against now.
func Compare(then, now Bookmark) Diff {
	d := Diff{Bookmark: then, Now: now, Changes: []Change{}}
	names := map[string]bool{}
	for h := range then.Hosts {
		names[h] = true
	}
	for h := range now.Hosts {
		names[h] = true
	}
	sorted := make([]string, 0, len(names))
	for h := range names {
		sorted = append(sorted, h)
	}
	sort.Strings(sorted)
	add := func(c Change) {
		if c.Better {
			d.Better++
		}
		if c.Worse {
			d.Worse++
		}
		d.Changes = append(d.Changes, c)
	}
	for _, h := range sorted {
		a, hadA := then.Hosts[h]
		b, hasB := now.Hosts[h]
		switch {
		case hadA && !hasB:
			add(Change{Host: h, Kind: "host-removed", Detail: "no longer in the inventory"})
			continue
		case !hadA && hasB:
			add(Change{Host: h, Kind: "host-added", Detail: fmt.Sprintf("new host (posture %d, risk %d)", b.Posture, b.Risk)})
			continue
		}
		changed := false
		if a.Posture != b.Posture {
			add(Change{Host: h, Kind: "posture", Detail: fmt.Sprintf("posture %d → %d", a.Posture, b.Posture), Better: b.Posture > a.Posture, Worse: b.Posture < a.Posture})
			changed = true
		}
		if a.Compliance != b.Compliance {
			add(Change{Host: h, Kind: "compliance", Detail: fmt.Sprintf("compliance %d%% → %d%%", a.Compliance, b.Compliance), Better: b.Compliance > a.Compliance, Worse: b.Compliance < a.Compliance})
			changed = true
		}
		if a.Risk != b.Risk {
			add(Change{Host: h, Kind: "risk", Detail: fmt.Sprintf("risk %d → %d", a.Risk, b.Risk), Better: b.Risk < a.Risk, Worse: b.Risk > a.Risk})
			changed = true
		}
		if a.Vulns != b.Vulns {
			add(Change{Host: h, Kind: "vulns", Detail: fmt.Sprintf("known vulnerabilities %d → %d", a.Vulns, b.Vulns), Better: b.Vulns < a.Vulns, Worse: b.Vulns > a.Vulns})
			changed = true
		}
		if a.ShadowAI != b.ShadowAI {
			add(Change{Host: h, Kind: "shadow-ai", Detail: fmt.Sprintf("shadow AI tools %d → %d", a.ShadowAI, b.ShadowAI), Better: b.ShadowAI < a.ShadowAI, Worse: b.ShadowAI > a.ShadowAI})
			changed = true
		}
		if a.Stale != b.Stale {
			if b.Stale {
				add(Change{Host: h, Kind: "stale", Detail: "stopped reporting", Worse: true})
			} else {
				add(Change{Host: h, Kind: "recovered", Detail: "reporting again", Better: true})
			}
			changed = true
		}
		if a.Group != b.Group {
			add(Change{Host: h, Kind: "group", Detail: fmt.Sprintf("moved from group %q to %q", a.Group, b.Group)})
			changed = true
		}
		if !changed {
			d.Unchanged++
		}
	}
	if then.Rules != now.Rules {
		add(Change{Kind: "rules", Detail: fmt.Sprintf("policy rules %d → %d", then.Rules, now.Rules)})
	}
	if then.Assets != now.Assets {
		add(Change{Kind: "assets", Detail: fmt.Sprintf("discovered assets %d → %d", then.Assets, now.Assets), Worse: now.Assets > then.Assets})
	}
	d.Summary = fmt.Sprintf("Since %s (%s): %d host(s) then, %d now; average posture %d → %d, average risk %d → %d; %d change(s), %d better, %d worse.",
		then.Name, then.CreatedAt.Format("Jan 2 15:04"), len(then.Hosts), len(now.Hosts), then.AvgPosture, now.AvgPosture, then.AvgRisk, now.AvgRisk, len(d.Changes), d.Better, d.Worse)
	return d
}
