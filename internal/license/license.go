/*******************************************************************************
 * @file         license.go
 * @brief        Package license implements the license and seat usage
 *               dashboard (#32) -- active-seat vs licensed-seat tracking,
 *               a historical usage trend, and an approaching-limit check.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package license answers the question procurement always asks: how is
// usage tracked against the contract. It builds entirely on the
// existing internal/directory user directory (introduced for #22) as
// the source of truth for "active seat" -- there is no separate seat
// concept to keep in sync -- and persists one usage snapshot per day via
// the existing store.Document mechanism, the same pattern used by
// internal/directory, internal/acl, and internal/mfa.
//
// A "seat" here is one active (non-deactivated) entry in the user
// directory. LicensedSeats is an operator-configured ceiling (flag/env,
// see cmd/topotrace/main.go), not something this package enforces --
// TopoTrace does not block logins at the seat limit, it reports on it,
// consistent with the issue's framing ("how usage is tracked against
// contract", not "stop the Nth user from logging in").
package license

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"topotrace/internal/directory"
	"topotrace/internal/model"
	"topotrace/internal/store"
)

// DocumentKind is the store.Document kind used for daily usage
// snapshots, one document per calendar day (UTC), keyed by date.
const DocumentKind = "seat_usage_snapshot"

// dateLayout is the snapshot document ID format -- also what makes
// History's lexicographic sort equivalent to chronological order.
const dateLayout = "2006-01-02"

// Snapshot is one day's recorded usage.
type Snapshot struct {
	Date          string    `json:"date"` // YYYY-MM-DD, UTC
	ActiveUsers   int       `json:"active_users"`
	LicensedSeats int       `json:"licensed_seats"`
	RecordedAt    time.Time `json:"recorded_at"`
}

// UsagePct returns active/licensed as a percentage, 0 if LicensedSeats
// is not configured (<= 0) -- a deliberately permissive default so an
// unconfigured deployment reports usage without a divide-by-zero or a
// false "at limit" alarm.
func (s Snapshot) UsagePct() float64 {
	if s.LicensedSeats <= 0 {
		return 0
	}
	return 100 * float64(s.ActiveUsers) / float64(s.LicensedSeats)
}

// ActiveSeats counts active directory users -- the current seat usage,
// computed live rather than cached, since internal/directory is
// already the cheap-to-list source of truth.
func ActiveSeats(ctx context.Context, st store.Store) (int, error) {
	users, err := directory.List(ctx, st)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.Active {
			n++
		}
	}
	return n, nil
}

// RecordSnapshot computes today's active-seat count and persists it as
// today's snapshot, overwriting any earlier snapshot recorded the same
// UTC day (so calling this more than once a day, e.g. on every admin
// dashboard load, doesn't pile up duplicate history entries).
func RecordSnapshot(ctx context.Context, st store.Store, licensedSeats int) (Snapshot, error) {
	active, err := ActiveSeats(ctx, st)
	if err != nil {
		return Snapshot{}, err
	}
	now := time.Now().UTC()
	snap := Snapshot{
		Date:          now.Format(dateLayout),
		ActiveUsers:   active,
		LicensedSeats: licensedSeats,
		RecordedAt:    now,
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return Snapshot{}, err
	}
	if err := st.PutDocument(ctx, model.Document{Kind: DocumentKind, ID: snap.Date, Data: data}); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// History returns recorded snapshots newest-first, capped at limit (0
// or negative means unbounded). It does not itself record today's
// snapshot -- callers that want "today" included call RecordSnapshot
// first (handleLicenseUsage in internal/api/enterprise.go does this).
func History(ctx context.Context, st store.Store, limit int) ([]Snapshot, error) {
	docs, err := st.ListDocuments(ctx, DocumentKind)
	if err != nil {
		return nil, err
	}
	snaps := make([]Snapshot, 0, len(docs))
	for _, d := range docs {
		var s Snapshot
		if err := json.Unmarshal(d.Data, &s); err != nil {
			continue // a malformed snapshot doesn't break the whole trend
		}
		snaps = append(snaps, s)
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Date > snaps[j].Date })
	if limit > 0 && len(snaps) > limit {
		snaps = snaps[:limit]
	}
	return snaps, nil
}

// NearLimitThresholdPct is the default "approaching the seat limit"
// warning threshold -- 90% of licensed seats.
const NearLimitThresholdPct = 90.0

// NearLimit reports whether active usage is at or above thresholdPct of
// licensed seats. A LicensedSeats of 0 or less (unconfigured) is never
// "near limit" -- there's nothing to compare against.
func NearLimit(active, licensedSeats int, thresholdPct float64) bool {
	if licensedSeats <= 0 {
		return false
	}
	return 100*float64(active)/float64(licensedSeats) >= thresholdPct
}

// AlertMessage returns a short, human-readable warning for a
// near-or-over-limit snapshot, or "" if not near the limit. Callers
// (the API layer) decide what to do with a non-empty message -- audit
// log, SIEM export via the existing siemforward pipeline, etc.
func AlertMessage(active, licensedSeats int, thresholdPct float64) string {
	if !NearLimit(active, licensedSeats, thresholdPct) {
		return ""
	}
	if active > licensedSeats {
		return fmt.Sprintf("seat usage (%d) has exceeded the licensed seat count (%d)", active, licensedSeats)
	}
	return fmt.Sprintf("seat usage (%d) is approaching the licensed seat count (%d)", active, licensedSeats)
}
