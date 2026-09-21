/*******************************************************************************
 * @file         agenthealth.go
 * @brief        Package agenthealth tracks the agents themselves, separately from the data they report: when each host's agent last checked in, how regularly it has been checking in, whether it's late against its own cadence, and how many reports failed...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package agenthealth tracks the agents themselves, separately from the
// data they report: when each host's agent last checked in, how
// regularly it has been checking in, whether it's late against its own
// cadence, and how many reports failed (bad token, unparseable
// payload, cook error). "Stale" only says a host hasn't reported in 24
// hours; this says the agent that usually reports every 30 minutes is
// 3 hours late, or that something is presenting a wrong token for a
// host name every five minutes -- the observability question about the
// collectors, not the collected.
//
// One model.Document per host (Kind "agent_health"), updated by the
// ingest paths on every report attempt.
package agenthealth

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

// Kind is the model.Document kind this package owns.
const Kind = "agent_health"

// keepIntervals is how many recent check-in gaps are kept for cadence.
const keepIntervals = 20

// Record is one host's agent health.
type Record struct {
	Host          string    `json:"host"`
	Path          string    `json:"path,omitempty"` // "tcp", "mobile", "airgap", "cloud" -- how the last report arrived
	Checkins      int       `json:"checkins"`
	LastCheckin   time.Time `json:"last_checkin"`
	Intervals     []float64 `json:"intervals_sec,omitempty"` // recent gaps between check-ins, seconds
	Failures      int       `json:"failures"`
	LastFailure   time.Time `json:"last_failure,omitempty"`
	LastFailureAt string    `json:"last_failure_reason,omitempty"`
	LastChanges   int       `json:"last_changes"`
}

// Status is a Record evaluated as of now.
type Status struct {
	Record
	ExpectedEverySec float64 `json:"expected_every_sec"` // median of recent intervals; 0 when unknown
	LateBySec        float64 `json:"late_by_sec"`        // how far past 2x the expected cadence; 0 when on time
	State            string  `json:"state"`              // "healthy", "late", "missing", "never", "failing"
	Detail           string  `json:"detail"`
}

func load(ctx context.Context, st store.Store, host string) (Record, error) {
	doc, ok, err := st.GetDocument(ctx, Kind, host)
	if err != nil || !ok {
		return Record{Host: host}, err
	}
	var r Record
	if err := json.Unmarshal(doc.Data, &r); err != nil {
		return Record{Host: host}, err
	}
	r.Host = host
	return r, nil
}

func save(ctx context.Context, st store.Store, r Record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return st.PutDocument(ctx, model.Document{Kind: Kind, ID: r.Host, Data: data})
}

// Checkin records a successful report for host.
func Checkin(ctx context.Context, st store.Store, host, path string, changes int, now time.Time) error {
	r, err := load(ctx, st, host)
	if err != nil {
		return err
	}
	if !r.LastCheckin.IsZero() {
		gap := now.Sub(r.LastCheckin).Seconds()
		if gap > 0 {
			r.Intervals = append(r.Intervals, gap)
			if len(r.Intervals) > keepIntervals {
				r.Intervals = r.Intervals[len(r.Intervals)-keepIntervals:]
			}
		}
	}
	r.Checkins++
	r.LastCheckin = now
	r.Path = path
	r.LastChanges = changes
	return save(ctx, st, r)
}

// Failure records a failed report attempt for host (bad token, bad
// payload, cook error).
func Failure(ctx context.Context, st store.Store, host, reason string, now time.Time) error {
	r, err := load(ctx, st, host)
	if err != nil {
		return err
	}
	r.Failures++
	r.LastFailure = now
	r.LastFailureAt = reason
	return save(ctx, st, r)
}

// Evaluate turns a Record into a Status as of now.
func Evaluate(r Record, now time.Time) Status {
	s := Status{Record: r}
	if len(r.Intervals) > 0 {
		sorted := append([]float64(nil), r.Intervals...)
		sort.Float64s(sorted)
		s.ExpectedEverySec = sorted[len(sorted)/2]
	}
	recentFailure := !r.LastFailure.IsZero() && now.Sub(r.LastFailure) < 24*time.Hour && r.LastFailure.After(r.LastCheckin)
	switch {
	case r.LastCheckin.IsZero() && r.Failures > 0:
		s.State, s.Detail = "failing", "no successful report yet; last failure: "+r.LastFailureAt
	case r.LastCheckin.IsZero():
		s.State, s.Detail = "never", "no agent report recorded"
	case now.Sub(r.LastCheckin) > 24*time.Hour:
		s.State, s.Detail = "missing", "last report "+humanAgo(now.Sub(r.LastCheckin))+" ago (past the 24h staleness window)"
	case recentFailure:
		s.State, s.Detail = "failing", "reports are failing since the last success: "+r.LastFailureAt
	case s.ExpectedEverySec > 0 && now.Sub(r.LastCheckin).Seconds() > 2*s.ExpectedEverySec:
		s.LateBySec = now.Sub(r.LastCheckin).Seconds() - 2*s.ExpectedEverySec
		s.State, s.Detail = "late", "usually reports every "+humanAgo(time.Duration(s.ExpectedEverySec)*time.Second)+", last seen "+humanAgo(now.Sub(r.LastCheckin))+" ago"
	default:
		s.State, s.Detail = "healthy", "last report "+humanAgo(now.Sub(r.LastCheckin))+" ago"
		if s.ExpectedEverySec > 0 {
			s.Detail += ", cadence about every " + humanAgo(time.Duration(s.ExpectedEverySec)*time.Second)
		}
	}
	return s
}

// All returns every host's evaluated status, worst first.
func All(ctx context.Context, st store.Store, now time.Time) ([]Status, error) {
	docs, err := st.ListDocuments(ctx, Kind)
	if err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(docs))
	for _, d := range docs {
		var r Record
		if json.Unmarshal(d.Data, &r) != nil {
			continue
		}
		r.Host = d.ID
		out = append(out, Evaluate(r, now))
	}
	rank := map[string]int{"failing": 0, "missing": 1, "late": 2, "never": 3, "healthy": 4}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].State] != rank[out[j].State] {
			return rank[out[i].State] < rank[out[j].State]
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

// Get returns one host's status.
func Get(ctx context.Context, st store.Store, host string, now time.Time) (Status, error) {
	r, err := load(ctx, st, host)
	return Evaluate(r, now), err
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	default:
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	}
}
