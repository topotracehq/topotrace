// Package memstore is Muster's reference Store implementation: an
// in-memory map guarded by a mutex, snapshotted to a JSON file on every
// write so a restart doesn't lose data. It's not meant to be the
// long-term backend -- Postgres is the obvious next step once this needs
// to survive more than a demo -- but it means Muster runs with zero
// external services: `go run ./cmd/muster` and nothing else.
package memstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

type snapshot struct {
	Hosts   map[string]model.Host            `json:"hosts"`
	Facts   map[string]map[string]model.Fact `json:"facts"` // host -> category -> fact
	Changes []model.Change                   `json:"changes,omitempty"`
}

// Store is a concurrency-safe, optionally file-backed Store implementation.
type Store struct {
	mu      sync.Mutex
	path    string // empty means in-memory only, no persistence
	hosts   map[string]model.Host
	facts   map[string]map[string]model.Fact
	changes []model.Change
}

// New creates a Store. If path is non-empty, existing state is loaded
// from it (if present) and every write re-snapshots the full state back
// to that path.
func New(path string) (*Store, error) {
	s := &Store{
		path:  path,
		hosts: make(map[string]model.Host),
		facts: make(map[string]map[string]model.Fact),
	}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("memstore: reading %s: %w", path, err)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("memstore: parsing %s: %w", path, err)
	}
	if snap.Hosts != nil {
		s.hosts = snap.Hosts
	}
	if snap.Facts != nil {
		s.facts = snap.Facts
	}
	if snap.Changes != nil {
		s.changes = snap.Changes
	}
	return s, nil
}

// persist must be called with s.mu held.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	snap := snapshot{Hosts: s.hosts, Facts: s.facts, Changes: s.changes}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) UpsertHost(_ context.Context, host model.Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.hosts[host.Name]; ok {
		if host.FirstSeen.IsZero() {
			host.FirstSeen = existing.FirstSeen
		}
		// Group/Tags are operator-assigned via SetHostGroup/SetHostTags,
		// never carried in what the cook pipeline passes here -- preserve
		// whatever's already on record the same way FirstSeen is.
		if host.Group == "" {
			host.Group = existing.Group
		}
		if host.Tags == nil {
			host.Tags = existing.Tags
		}
	} else if host.FirstSeen.IsZero() {
		host.FirstSeen = time.Now().UTC()
	}
	s.hosts[host.Name] = host
	return s.persist()
}

func (s *Store) SetHostGroup(_ context.Context, name, group string) (model.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[name]
	if !ok {
		return model.Host{}, store.ErrHostNotFound
	}
	h.Group = group
	s.hosts[name] = h
	if err := s.persist(); err != nil {
		return model.Host{}, err
	}
	return h, nil
}

func (s *Store) SetHostTags(_ context.Context, name string, tags []string) (model.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[name]
	if !ok {
		return model.Host{}, store.ErrHostNotFound
	}
	h.Tags = tags
	s.hosts[name] = h
	if err := s.persist(); err != nil {
		return model.Host{}, err
	}
	return h, nil
}

func (s *Store) GetHost(_ context.Context, name string) (model.Host, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[name]
	return h, ok, nil
}

func (s *Store) ListHosts(_ context.Context) ([]model.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) UpsertFact(_ context.Context, fact model.Fact) ([]model.Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.facts[fact.Host]; !ok {
		s.facts[fact.Host] = make(map[string]model.Fact)
	}
	previous, hadPrevious := s.facts[fact.Host][fact.Category]

	var changes []model.Change
	if hadPrevious {
		changes = store.Diff(fact.Host, fact.Category, previous.Data, fact.Data)
		changes = store.WithTimestamp(changes, fact.CookedAt)
		s.changes = append(s.changes, changes...)
	}

	s.facts[fact.Host][fact.Category] = fact
	if err := s.persist(); err != nil {
		return nil, err
	}
	return changes, nil
}

func (s *Store) GetFact(_ context.Context, host, category string) (model.Fact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byCat, ok := s.facts[host]
	if !ok {
		return model.Fact{}, false, nil
	}
	f, ok := byCat[category]
	return f, ok, nil
}

func (s *Store) ListFacts(_ context.Context, host string) ([]model.Fact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byCat, ok := s.facts[host]
	out := make([]model.Fact, 0, len(byCat))
	if !ok {
		return out, nil
	}
	for _, f := range byCat {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out, nil
}

// ListChanges returns host's recorded changes, newest first, capped at
// limit (<= 0 means unbounded).
func (s *Store) ListChanges(_ context.Context, host string, limit int) ([]model.Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := []model.Change{}
	for _, c := range s.changes {
		if c.Host == host {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChangedAt.After(out[j].ChangedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) Query(_ context.Context, category, field, contains string) ([]model.Fact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := []model.Fact{}
	for _, byCat := range s.facts {
		fact, ok := byCat[category]
		if !ok {
			continue
		}
		val, ok := fact.Data[field]
		if !ok {
			continue
		}
		if containsSubstring(fmt.Sprintf("%v", val), contains) {
			out = append(out, fact)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

func containsSubstring(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// compile-time check that Store satisfies store.Store.
var _ store.Store = (*Store)(nil)
