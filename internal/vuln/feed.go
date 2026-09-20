/*******************************************************************************
 * @file         feed.go
 * @brief        Package vuln's live feed: a small, best-effort supplement to the static Dataset, pulled from OSV.dev (https://osv.dev/docs/#tag/api) -- a free, no-API-key-required vulnerability database covering, among others, the Debian ecosystem this project's dataset already targets.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package vuln's live feed: a small, best-effort supplement to the
// static Dataset, pulled from OSV.dev (https://osv.dev/docs/#tag/api) --
// a free, no-API-key-required vulnerability database covering, among
// others, the Debian ecosystem this project's dataset already targets.
// This is deliberately NOT a general-purpose OSV client: it only ever
// queries Watchlist's fixed set of package names, on an interval, and
// only ever contributes entries Check/CheckWithFeed can use the exact
// same way as a hand-typed Dataset entry -- one package name, one
// known-vulnerable version ceiling, one CVE-ish ID, one severity, one
// description. Anything OSV returns that doesn't fit that shape (no
// "fixed" version in any range, for instance) is skipped rather than
// guessed at.
//
// Honesty about what this isn't, same as everywhere else in this
// project: it's still a fixed watch-list, not "every package this host
// happens to have installed" -- OSV supports querying by exact
// name+ecosystem, not "show me everything," so broadening coverage
// means growing Watchlist deliberately, not automatically. And a
// refresh failure (network down, OSV rate-limiting, a malformed
// response) never blanks out what was fetched last -- see refresh's
// doc comment.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Watchlist is the fixed set of package names the live feed queries,
// all against the "Debian" ecosystem -- deliberately the same packages
// Dataset already covers by hand, so turning the feed on doesn't
// suddenly start flagging packages nobody asked about. Add to this
// list and to Dataset together, not one without the other.
var Watchlist = []string{
	"bash", "sudo", "openssh-server", "openssl", "libssl1.1",
	"curl", "libcurl4", "zlib1g", "sqlite3", "apt",
}

// osvQueryURL is OSV.dev's single-package query endpoint. No API key,
// no auth header -- OSV is a free, public service.
const osvQueryURL = "https://api.osv.dev/v1/query"

// Feed periodically refreshes a live supplement to Dataset. Safe for
// concurrent use: Entries() may be called from any goroutine while
// Run's background refresh is in progress.
type Feed struct {
	client *http.Client
	log    *slog.Logger

	mu   sync.RWMutex
	live []Entry
}

// NewFeed returns a Feed with no entries yet -- call Run to start
// refreshing it, or Entries() returns empty until the first successful
// refresh completes.
func NewFeed(log *slog.Logger) *Feed {
	if log == nil {
		log = slog.Default()
	}
	return &Feed{
		client: &http.Client{Timeout: 10 * time.Second},
		log:    log,
	}
}

// Run blocks, refreshing on interval (fetching once immediately first)
// until ctx is done. Meant to be started with `go feed.Run(ctx,
// interval)` from cmd/muster's main, the same pattern as
// evaluator.Evaluator.Run.
func (f *Feed) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	f.refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.refresh(ctx)
		}
	}
}

// refresh queries OSV.dev for every package in Watchlist and, only if
// at least one query succeeded, replaces the cached live entries with
// whatever came back. A total outage (every query failing) leaves the
// existing cache untouched rather than blanking coverage back down to
// Dataset alone -- a live feed that's temporarily unreachable should
// degrade to "stale," not "silently worse than not having one."
func (f *Feed) refresh(ctx context.Context) {
	var entries []Entry
	var successes int
	for _, pkg := range Watchlist {
		got, err := f.queryOSV(ctx, pkg)
		if err != nil {
			f.log.Warn("vuln feed: querying OSV", "package", pkg, "err", err)
			continue
		}
		successes++
		entries = append(entries, got...)
	}
	if successes == 0 {
		f.log.Warn("vuln feed: every OSV query failed this cycle, keeping previous entries", "watchlist_size", len(Watchlist))
		return
	}
	f.mu.Lock()
	f.live = entries
	f.mu.Unlock()
	f.log.Info("vuln feed: refreshed", "entries", len(entries), "packages_queried", successes, "watchlist_size", len(Watchlist))
}

// Entries returns a copy of the most recently fetched live entries --
// empty (never nil) before the first successful refresh.
func (f *Feed) Entries() []Entry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Entry, len(f.live))
	copy(out, f.live)
	return out
}

// osvQueryRequest is OSV.dev's query-by-package request body.
type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

// osvVuln is the small subset of OSV's vulnerability schema this
// package actually reads -- OSV's real schema has many more fields
// (references, credits, database-specific data, ...) that Check/
// CheckWithFeed has no use for and this deliberately never parses.
type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// queryOSV fetches every known vulnerability OSV has for pkg (ecosystem
// "Debian") and converts each one that has an extractable "fixed"
// version into an Entry. A vuln with no "fixed" event in any range is
// skipped outright -- Check/CheckWithFeed need a concrete version
// ceiling to compare against, and guessing one would be worse than not
// reporting it.
func (f *Feed) queryOSV(ctx context.Context, pkg string) ([]Entry, error) {
	var reqBody osvQueryRequest
	reqBody.Package.Name = pkg
	reqBody.Package.Ecosystem = "Debian"
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("encoding query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
		return nil, fmt.Errorf("OSV replied %s", resp.Status)
	}

	var parsed osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	var entries []Entry
	for _, v := range parsed.Vulns {
		fixed := firstFixedVersion(v)
		if fixed == "" {
			continue
		}
		entries = append(entries, Entry{
			Package:     pkg,
			MaxVersion:  fixed,
			CVE:         bestID(v),
			Severity:    bestSeverity(v),
			Description: bestDescription(v),
		})
	}
	return entries, nil
}

// firstFixedVersion returns the first "fixed" event value found across
// every range of every affected entry -- OSV can list several ranges
// (different branches/distros), and this deliberately takes the first
// one rather than trying to reconcile them, the same "best-effort, not
// exhaustive" spirit as internal/vuln's own compareVersions.
func firstFixedVersion(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// bestID prefers a CVE alias (what the rest of this project, and most
// people reading a vulnerability report, actually recognize) and falls
// back to OSV's own ID (a GHSA-/DEBIAN- style identifier) when no CVE
// alias exists.
func bestID(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// bestSeverity maps OSV's CVSS score (when present) to the same
// low/medium/high/critical scale Dataset's hand-typed entries use --
// OSV doesn't always carry a parsed severity for older/Debian-sourced
// entries, in which case this returns "unknown" rather than guessing.
func bestSeverity(v osvVuln) string {
	for _, sev := range v.Severity {
		if sev.Type != "CVSS_V3" && sev.Type != "CVSS_V2" {
			continue
		}
		score := leadingCVSSScore(sev.Score)
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		case score > 0:
			return "low"
		}
	}
	return "unknown"
}

// leadingCVSSScore best-effort-parses a numeric score out of a CVSS
// vector/score string -- OSV's Severity.Score is sometimes a bare
// number ("7.5") and sometimes a full vector string
// ("CVSS:3.1/AV:N/AC:L/.../S:U/C:H/I:H/A:H"), which doesn't carry a
// precomputed numeric score at all. This only handles the bare-number
// case; a vector string with no leading number returns 0 (treated the
// same as "no severity data").
func leadingCVSSScore(s string) float64 {
	var whole, frac int
	n, _ := fmt.Sscanf(s, "%d.%d", &whole, &frac)
	if n < 1 {
		return 0
	}
	score := float64(whole)
	if n == 2 {
		score += float64(frac) / 10
	}
	return score
}

// bestDescription prefers Summary (short, one-line, exactly what
// Dataset's hand-typed Description entries already look like) and falls
// back to a truncated Details when Summary is empty.
func bestDescription(v osvVuln) string {
	if v.Summary != "" {
		return v.Summary
	}
	const maxLen = 200
	d := v.Details
	if len(d) > maxLen {
		d = d[:maxLen] + "..."
	}
	return d
}
