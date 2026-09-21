/*******************************************************************************
 * @file         ueba.go
 * @brief        Package ueba is a small set of behavioral heuristics over Muster's own audit trail -- the user-and-entity-behavior-analytics idea (who is doing something unusual?) applied to the one dataset this project already has about its operators: ...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package ueba is a small set of behavioral heuristics over Muster's
// own audit trail -- the user-and-entity-behavior-analytics idea (who is
// doing something unusual?) applied to the one dataset this project
// already has about its operators: every authenticated write, keyed by
// actor and time. Explainable rules, not a model: an actor acting at an
// unusual hour, a burst of writes, a new admin credential, a run of
// remediations, a settings change, an actor nobody's seen before. Each
// signal says which rule fired and why, so it can be triaged rather
// than trusted.
//
// Stated plainly: this is illustrative of the pattern, not a UEBA
// product. There is no baseline-per-user learning, no peer grouping,
// no scoring model -- those are what the real thing adds on top of
// exactly this kind of rule.
package ueba

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"muster/internal/model"
)

// Signal is one behavioral finding.
type Signal struct {
	Kind     string    `json:"kind"`     // "off-hours", "burst", "new-admin-key", "remediation-run", "settings-change", "new-actor", "mass-delete"
	Severity string    `json:"severity"` // "low", "medium", "high"
	Actor    string    `json:"actor"`
	At       time.Time `json:"at"`
	Count    int       `json:"count,omitempty"`
	Detail   string    `json:"detail"`
	Examples []string  `json:"examples,omitempty"` // audit entry IDs
}

// Options tune the heuristics.
type Options struct {
	Now           time.Time
	Window        time.Duration // how far back to look (default 7 days)
	BusinessStart int           // hour of day, local time (default 7)
	BusinessEnd   int           // hour of day, local time (default 19)
	BurstCount    int           // writes within BurstWindow that count as a burst (default 10)
	BurstWindow   time.Duration // default 10 minutes
	Location      *time.Location
}

func (o *Options) defaults() {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Window <= 0 {
		o.Window = 7 * 24 * time.Hour
	}
	if o.BusinessStart == 0 && o.BusinessEnd == 0 {
		o.BusinessStart, o.BusinessEnd = 7, 19
	}
	if o.BurstCount <= 0 {
		o.BurstCount = 10
	}
	if o.BurstWindow <= 0 {
		o.BurstWindow = 10 * time.Minute
	}
	if o.Location == nil {
		o.Location = time.Local
	}
}

// systemActors are not people and are exempt from the people rules.
var systemActors = map[string]bool{"system": true, "seed-tool": true, "anonymous": true, "": true}

// writeActions are the audit actions that change something (as opposed
// to Ask Muster queries or logins).
func isWrite(action string) bool {
	switch {
	case strings.HasPrefix(action, "create-"), strings.HasPrefix(action, "delete-"), strings.HasPrefix(action, "patch-"),
		action == "queue-action", action == "settings_updated", action == "remediation-approved", action == "remediation-rejected",
		action == "baseline-captured", action == "baseline-cleared", action == "alert-snoozed", action == "notification-test":
		return true
	}
	return false
}

// Analyze runs every heuristic over entries (any order) and returns the
// signals, most severe and most recent first.
func Analyze(entries []model.AuditEntry, opts Options) []Signal {
	opts.defaults()
	cutoff := opts.Now.Add(-opts.Window)
	var recent []model.AuditEntry
	firstSeen := map[string]time.Time{}
	for _, e := range entries {
		if t, ok := firstSeen[e.Actor]; !ok || e.CreatedAt.Before(t) {
			firstSeen[e.Actor] = e.CreatedAt
		}
		if !e.CreatedAt.Before(cutoff) {
			recent = append(recent, e)
		}
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].CreatedAt.Before(recent[j].CreatedAt) })

	var out []Signal
	byActor := map[string][]model.AuditEntry{}
	for _, e := range recent {
		if systemActors[e.Actor] {
			continue
		}
		byActor[e.Actor] = append(byActor[e.Actor], e)
	}

	for actor, es := range byActor {
		// off-hours writes
		var off []model.AuditEntry
		for _, e := range es {
			if !isWrite(e.Action) {
				continue
			}
			h := e.CreatedAt.In(opts.Location).Hour()
			wd := e.CreatedAt.In(opts.Location).Weekday()
			if h < opts.BusinessStart || h >= opts.BusinessEnd || wd == time.Saturday || wd == time.Sunday {
				off = append(off, e)
			}
		}
		if len(off) > 0 {
			out = append(out, Signal{Kind: "off-hours", Severity: "low", Actor: actor, At: off[len(off)-1].CreatedAt, Count: len(off),
				Detail:   fmt.Sprintf("%d write(s) outside %02d:00-%02d:00 %s / on a weekend, most recently %s", len(off), opts.BusinessStart, opts.BusinessEnd, opts.Location, off[len(off)-1].Action),
				Examples: ids(off)})
		}

		// bursts of writes
		var writes []model.AuditEntry
		for _, e := range es {
			if isWrite(e.Action) {
				writes = append(writes, e)
			}
		}
		for i := 0; i+opts.BurstCount-1 < len(writes); i++ {
			j := i + opts.BurstCount - 1
			if writes[j].CreatedAt.Sub(writes[i].CreatedAt) <= opts.BurstWindow {
				out = append(out, Signal{Kind: "burst", Severity: "medium", Actor: actor, At: writes[j].CreatedAt, Count: opts.BurstCount,
					Detail:   fmt.Sprintf("%d writes within %s (%s ... %s)", opts.BurstCount, opts.BurstWindow, writes[i].Action, writes[j].Action),
					Examples: ids(writes[i : j+1])})
				break
			}
		}

		// remediation runs
		var rem []model.AuditEntry
		for _, e := range es {
			if e.Action == "queue-action" || e.Action == "remediation-approved" {
				rem = append(rem, e)
			}
		}
		if len(rem) >= 3 {
			out = append(out, Signal{Kind: "remediation-run", Severity: "medium", Actor: actor, At: rem[len(rem)-1].CreatedAt, Count: len(rem),
				Detail: fmt.Sprintf("%d remediation actions queued or approved in the window", len(rem)), Examples: ids(rem)})
		}

		// mass deletes
		var dels []model.AuditEntry
		for _, e := range es {
			if strings.HasPrefix(e.Action, "delete-") {
				dels = append(dels, e)
			}
		}
		if len(dels) >= 3 {
			out = append(out, Signal{Kind: "mass-delete", Severity: "medium", Actor: actor, At: dels[len(dels)-1].CreatedAt, Count: len(dels),
				Detail: fmt.Sprintf("%d delete actions in the window (%s)", len(dels), summarizeActions(dels)), Examples: ids(dels)})
		}

		// per-event notables
		for _, e := range es {
			switch {
			case e.Action == "create-key" && strings.Contains(strings.ToLower(e.Detail), "admin"):
				out = append(out, Signal{Kind: "new-admin-key", Severity: "high", Actor: actor, At: e.CreatedAt, Count: 1,
					Detail: "an admin-role API key was created: " + e.Detail, Examples: []string{e.ID}})
			case e.Action == "settings_updated":
				out = append(out, Signal{Kind: "settings-change", Severity: "medium", Actor: actor, At: e.CreatedAt, Count: 1,
					Detail: "server settings changed: " + e.Detail, Examples: []string{e.ID}})
			}
		}

		// actor never seen before this window
		if fs, ok := firstSeen[actor]; ok && !fs.Before(cutoff) {
			out = append(out, Signal{Kind: "new-actor", Severity: "low", Actor: actor, At: fs, Count: len(es),
				Detail: fmt.Sprintf("first activity ever from this actor was %s ago (%d entries since)", opts.Now.Sub(fs).Round(time.Minute), len(es)), Examples: ids(es[:min(3, len(es))])})
		}
	}

	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		return out[i].At.After(out[j].At)
	})
	return out
}

func ids(es []model.AuditEntry) []string {
	out := make([]string, 0, len(es))
	for i, e := range es {
		if i >= 5 {
			break
		}
		out = append(out, e.ID)
	}
	return out
}

func summarizeActions(es []model.AuditEntry) string {
	counts := map[string]int{}
	for _, e := range es {
		counts[e.Action]++
	}
	parts := make([]string, 0, len(counts))
	for a, n := range counts {
		parts = append(parts, fmt.Sprintf("%s x%d", a, n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
