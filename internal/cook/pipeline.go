package cook

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

// Pipeline finds the most recent raw capture directory for a host and
// cooks it into the store, dispatching to the right platform parser.
type Pipeline struct {
	RawBaseDir string // e.g. "./data/raw" -- raw/<platform>/<host>/<timestamp>/...
	Store      store.Store
}

// Cook processes the newest raw snapshot for (platform, host). Returns
// the field-level changes recorded against the previous cooked fact, if
// any -- same "what changed since last time" signal the store layer
// produces for every UpsertFact call.
func (p *Pipeline) Cook(ctx context.Context, platform, host string) ([]model.Change, error) {
	rawDir, err := p.latestSnapshot(platform, host)
	if err != nil {
		return nil, err
	}

	var data map[string]any
	switch platform {
	case "linux":
		data, err = CookLinux(rawDir)
	case "windows":
		data, err = CookWindows(rawDir)
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

	changes, err := p.Store.UpsertFact(ctx, model.Fact{
		Host:     host,
		Category: "system_summary",
		Data:     data,
		CookedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("cook: upserting fact: %w", err)
	}
	return changes, nil
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
