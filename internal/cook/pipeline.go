/*******************************************************************************
 * @file         pipeline.go
 * @brief        Part of the TopoTrace cook module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package cook

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"muster/internal/agenthealth"
	"muster/internal/model"
	"muster/internal/store"
)

// (sort was already imported for latestSnapshot's directory-name sort;
// Cook now also uses it for a stable category iteration order.)

// Pipeline finds the most recent raw capture directory for a host and
// cooks it into the store, dispatching to the right platform parser.
type Pipeline struct {
	// Path labels how reports reach this pipeline for agent-health
	// bookkeeping ("tcp" when empty; internal/api sets "airgap" on its
	// own copy).
	Path       string
	RawBaseDir string // e.g. "./data/raw" -- raw/<platform>/<host>/<timestamp>/...
	Store      store.Store
}

// Cook processes the newest raw snapshot for (platform, host), storing
// every fact category the platform's cook step can produce -- not just
// system_summary. Returns the combined field-level changes recorded
// across all of them against their previous cooked values, if any --
// same "what changed since last time" signal the store layer produces
// for every UpsertFact call, just flattened across categories.
func (p *Pipeline) Cook(ctx context.Context, platform, host string) ([]model.Change, error) {
	rawDir, err := p.latestSnapshot(platform, host)
	if err != nil {
		return nil, err
	}

	var categories map[string]map[string]any
	switch platform {
	case "linux":
		categories, err = CookLinuxCategories(rawDir)
	case "windows":
		categories, err = CookWindowsCategories(rawDir)
	case "darwin":
		categories, err = CookDarwinCategories(rawDir)
	default:
		return nil, fmt.Errorf("cook: no parser registered for platform %q", platform)
	}
	if err != nil {
		return nil, fmt.Errorf("cook: parsing %s: %w", rawDir, err)
	}

	now := time.Now().UTC()
	if err := p.Store.UpsertHost(ctx, model.Host{Name: host, Platform: platform, LastCooked: now}); err != nil {
		return nil, fmt.Errorf("cook: upserting host: %w", err)
	}

	// Sorted so a run's changes come back in a stable, predictable
	// category order -- useful for tests/logs, and costs nothing given
	// how few categories there are.
	names := make([]string, 0, len(categories))
	for name := range categories {
		names = append(names, name)
	}
	sort.Strings(names)

	var allChanges []model.Change
	for _, name := range names {
		changes, err := p.Store.UpsertFact(ctx, model.Fact{
			Host:     host,
			Category: name,
			Data:     categories[name],
			CookedAt: now,
		})
		if err != nil {
			return nil, fmt.Errorf("cook: upserting fact %q: %w", name, err)
		}
		allChanges = append(allChanges, changes...)
	}
	// Agent health is best-effort bookkeeping about the collector, never
	// a reason to fail the report that just succeeded.
	path := p.Path
	if path == "" {
		path = "tcp"
	}
	_ = agenthealth.Checkin(ctx, p.Store, host, path, len(allChanges), now)
	return allChanges, nil
}

// latestSnapshot returns the raw/<platform>/<host>/<snapshot> directory
// with the lexicographically greatest name -- snapshot directories are
// named as RFC3339-ish timestamps by the ingest layer, so that sorts
// newest-last.
func (p *Pipeline) latestSnapshot(platform, host string) (string, error) {
	hostDir := filepath.Join(p.RawBaseDir, platform, host)
	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return "", fmt.Errorf("cook: reading %s: %w", hostDir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("cook: no raw snapshots for %s/%s under %s", platform, host, hostDir)
	}
	sort.Strings(names)
	return filepath.Join(hostDir, names[len(names)-1]), nil
}
