/*******************************************************************************
 * @file         history.go
 * @brief        Package history keeps a per-host time series of the scores Muster otherwise only ever computes fresh per request -- posture, compliance, vulnerability count, staleness -- so the dashboard can show a trend ("this fleet's posture over the ...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package history keeps a per-host time series of the scores Muster
// otherwise only ever computes fresh per request -- posture, compliance,
// vulnerability count, staleness -- so the dashboard can show a trend
// ("this fleet's posture over the last 30 days") instead of a single
// number, and so time-to-remediate can be measured at all: without a
// record of when a host first fell out of compliance and when it came
// back, there is no way to know how long anything took to fix.
//
// One model.Document per host (Kind "score_history"), holding a capped
// slice of Points, appended by the background evaluator once per run
// (see internal/evaluator). Capped rather than unbounded because this
// lives inside one JSON document, not an indexed table: MaxPoints at a
// 5-minute evaluator interval is a little over a week of full-resolution
// history; anything older is thinned to one point per hour on the way
// out, so the document stays small while the trend stays visible.
package history

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

// Kind is the model.Document kind this package owns.
const Kind = "score_history"

// MaxPoints caps how many points one host keeps at full resolution.
const MaxPoints = 2500

// Point is one evaluator run's snapshot of a host's scores.
type Point struct {
	At         time.Time `json:"at"`
	Posture    int       `json:"posture"`
	Compliance int       `json:"compliance"`
	Vulns      int       `json:"vulns"`
	Stale      bool      `json:"stale"`
}

// Series is one host's full recorded history, oldest first.
type Series struct {
	Host   string  `json:"host"`
	Points []Point `json:"points"`
}

// Record appends p to host's series, thinning old points past MaxPoints.
func Record(ctx context.Context, st store.Store, host string, p Point) error {
	s, err := Get(ctx, st, host)
	if err != nil {
		return err
	}
	s.Host = host
	s.Points = append(s.Points, p)
	if len(s.Points) > MaxPoints {
		s.Points = thin(s.Points, MaxPoints)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.PutDocument(ctx, model.Document{Kind: Kind, ID: host, Data: data})
}

// Get returns host's series (empty, not an error, if none recorded yet).
func Get(ctx context.Context, st store.Store, host string) (Series, error) {
	doc, ok, err := st.GetDocument(ctx, Kind, host)
	if err != nil || !ok {
		return Series{Host: host}, err
	}
	var s Series
	if err := json.Unmarshal(doc.Data, &s); err != nil {
		return Series{Host: host}, err
	}
	s.Host = host
	return s, nil
}

// All returns every host's series.
func All(ctx context.Context, st store.Store) ([]Series, error) {
	docs, err := st.ListDocuments(ctx, Kind)
	if err != nil {
		return nil, err
	}
	out := make([]Series, 0, len(docs))
	for _, d := range docs {
		var s Series
		if err := json.Unmarshal(d.Data, &s); err != nil {
			continue
		}
		s.Host = d.ID
		out = append(out, s)
	}
	return out, nil
}

// thin keeps the newest half of points at full resolution and collapses
// everything older to at most one point per hour, until the total fits
// in max. It never drops the very first point, so "since first seen"
// stays anchored.
func thin(points []Point, max int) []Point {
	if len(points) <= max {
		return points
	}
	keepFrom := len(points) - max/2
	var older []Point
	var lastHour time.Time
	for _, p := range points[:keepFrom] {
		h := p.At.Truncate(time.Hour)
		if len(older) == 0 || !h.Equal(lastHour) {
			older = append(older, p)
			lastHour = h
		}
	}
	out := append(older, points[keepFrom:]...)
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

// Bucket is one time bucket of the fleet-wide rollup.
type Bucket struct {
	At            time.Time `json:"at"`
	Hosts         int       `json:"hosts"`
	AvgPosture    int       `json:"avg_posture"`
	AvgCompliance int       `json:"avg_compliance"`
	HostsWithVuln int       `json:"hosts_with_vulns"`
	StaleHosts    int       `json:"stale_hosts"`
}

// FleetRollup collapses every host's series into one bucket per step
// (e.g. one per day) over the window ending at now. A host contributes
// its latest point within each bucket; buckets with no data are omitted.
func FleetRollup(all []Series, now time.Time, window, step time.Duration) []Bucket {
	if step <= 0 {
		step = 24 * time.Hour
	}
	start := now.Add(-window)
	type acc struct {
		latest map[string]Point
	}
	buckets := map[time.Time]*acc{}
	for _, s := range all {
		for _, p := range s.Points {
			if p.At.Before(start) || p.At.After(now) {
				continue
			}
			b := start.Add(p.At.Sub(start).Truncate(step))
			a := buckets[b]
			if a == nil {
				a = &acc{latest: map[string]Point{}}
				buckets[b] = a
			}
			if prev, ok := a.latest[s.Host]; !ok || p.At.After(prev.At) {
				a.latest[s.Host] = p
			}
		}
	}
	keys := make([]time.Time, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	out := make([]Bucket, 0, len(keys))
	for _, k := range keys {
		a := buckets[k]
		b := Bucket{At: k, Hosts: len(a.latest)}
		sumP, sumC := 0, 0
		for _, p := range a.latest {
			sumP += p.Posture
			sumC += p.Compliance
			if p.Vulns > 0 {
				b.HostsWithVuln++
			}
			if p.Stale {
				b.StaleHosts++
			}
		}
		if b.Hosts > 0 {
			b.AvgPosture = sumP / b.Hosts
			b.AvgCompliance = sumC / b.Hosts
		}
		out = append(out, b)
	}
	return out
}

// Remediation is one measured "fell out of compliance, then came back"
// span for a host.
type Remediation struct {
	Host       string        `json:"host"`
	From       time.Time     `json:"from"`
	To         time.Time     `json:"to"`
	Duration   time.Duration `json:"-"`
	DurationHr float64       `json:"duration_hours"`
}

// MTTR is the fleet-wide time-to-remediate rollup.
type MTTR struct {
	MeanHours     float64       `json:"mean_hours"`   // over resolved spans in the window; 0 when none
	MedianHours   float64       `json:"median_hours"` //
	Resolved      int           `json:"resolved"`     // spans that closed inside the window
	StillOpen     int           `json:"still_open"`   // hosts currently non-compliant (span not yet closed)
	OldestOpenHrs float64       `json:"oldest_open_hours"`
	Spans         []Remediation `json:"spans,omitempty"`
}

// TimeToRemediate measures, per host, every span during which
// Compliance was below 100 (the host had at least one failing check),
// from the first point where it dipped to the first point where it was
// back at 100. Spans still open at the newest point count as StillOpen.
// Only spans that closed within window of now feed the mean/median.
func TimeToRemediate(all []Series, now time.Time, window time.Duration) MTTR {
	var out MTTR
	var durations []float64
	cutoff := now.Add(-window)
	for _, s := range all {
		var openSince time.Time
		var open bool
		for _, p := range s.Points {
			bad := p.Compliance < 100
			switch {
			case bad && !open:
				open, openSince = true, p.At
			case !bad && open:
				open = false
				if p.At.After(cutoff) {
					d := p.At.Sub(openSince)
					r := Remediation{Host: s.Host, From: openSince, To: p.At, Duration: d, DurationHr: d.Hours()}
					out.Spans = append(out.Spans, r)
					durations = append(durations, d.Hours())
				}
			}
		}
		if open {
			out.StillOpen++
			if age := now.Sub(openSince).Hours(); age > out.OldestOpenHrs {
				out.OldestOpenHrs = age
			}
		}
	}
	out.Resolved = len(durations)
	if len(durations) > 0 {
		sum := 0.0
		for _, d := range durations {
			sum += d
		}
		out.MeanHours = sum / float64(len(durations))
		sort.Float64s(durations)
		mid := len(durations) / 2
		if len(durations)%2 == 0 {
			out.MedianHours = (durations[mid-1] + durations[mid]) / 2
		} else {
			out.MedianHours = durations[mid]
		}
	}
	sort.Slice(out.Spans, func(i, j int) bool { return out.Spans[i].To.After(out.Spans[j].To) })
	if len(out.Spans) > 50 {
		out.Spans = out.Spans[:50]
	}
	return out
}
