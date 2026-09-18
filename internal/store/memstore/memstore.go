/*******************************************************************************
 * @file         memstore.go
 * @brief        Package memstore is Muster's reference Store implementation: an in-memory map guarded by a mutex, snapshotted to a JSON file on every write so a restart doesn't lose data.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

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
	Hosts            map[string]model.Host            `json:"hosts"`
	Facts            map[string]map[string]model.Fact `json:"facts"` // host -> category -> fact
	Changes          []model.Change                   `json:"changes,omitempty"`
	Actions          []model.Action                   `json:"actions,omitempty"`
	NextActionID     int                              `json:"next_action_id,omitempty"`
	Groups           []string                         `json:"groups,omitempty"`
	AuditLog         []model.AuditEntry               `json:"audit_log,omitempty"`
	NextAuditID      int                              `json:"next_audit_id,omitempty"`
	APIKeys          []model.APIKey                   `json:"api_keys,omitempty"`
	NextKeyID        int                              `json:"next_key_id,omitempty"`
	Rules            []model.Rule                     `json:"rules,omitempty"`
	NextRuleID       int                              `json:"next_rule_id,omitempty"`
	Enrollments      []model.Enrollment               `json:"enrollments,omitempty"`
	NextEnrollID     int                              `json:"next_enroll_id,omitempty"`
	SoftwareRules    []model.SoftwareRule             `json:"software_rules,omitempty"`
	NextSoftwareID   int                              `json:"next_software_id,omitempty"`
	DiscoveredAssets []model.DiscoveredAsset          `json:"discovered_assets,omitempty"`
	NextAssetID      int                              `json:"next_asset_id,omitempty"`
	Documents        []model.Document                 `json:"documents,omitempty"`
}

// Store is a concurrency-safe, optionally file-backed Store implementation.
type Store struct {
	mu               sync.Mutex
	path             string // empty means in-memory only, no persistence
	hosts            map[string]model.Host
	facts            map[string]map[string]model.Fact
	changes          []model.Change
	actions          []model.Action
	nextActionID     int
	groups           map[string]bool
	auditLog         []model.AuditEntry
	nextAuditID      int
	apiKeys          []model.APIKey
	nextKeyID        int
	rules            []model.Rule
	nextRuleID       int
	enrollments      []model.Enrollment
	nextEnrollID     int
	softwareRules    []model.SoftwareRule
	nextSoftwareID   int
	discoveredAssets []model.DiscoveredAsset
	nextAssetID      int
	documents        map[string]map[string]model.Document // kind -> id -> doc
}

// New creates a Store. If path is non-empty, existing state is loaded
// from it (if present) and every write re-snapshots the full state back
// to that path.
func New(path string) (*Store, error) {
	s := &Store{
		path:      path,
		hosts:     make(map[string]model.Host),
		facts:     make(map[string]map[string]model.Fact),
		groups:    make(map[string]bool),
		documents: make(map[string]map[string]model.Document),
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
	if snap.Actions != nil {
		s.actions = snap.Actions
	}
	s.nextActionID = snap.NextActionID
	for _, g := range snap.Groups {
		s.groups[g] = true
	}
	if snap.AuditLog != nil {
		s.auditLog = snap.AuditLog
	}
	s.nextAuditID = snap.NextAuditID
	if snap.APIKeys != nil {
		s.apiKeys = snap.APIKeys
	}
	s.nextKeyID = snap.NextKeyID
	if snap.Rules != nil {
		s.rules = snap.Rules
	}
	s.nextRuleID = snap.NextRuleID
	if snap.Enrollments != nil {
		s.enrollments = snap.Enrollments
	}
	s.nextEnrollID = snap.NextEnrollID
	if snap.SoftwareRules != nil {
		s.softwareRules = snap.SoftwareRules
	}
	s.nextSoftwareID = snap.NextSoftwareID
	if snap.DiscoveredAssets != nil {
		s.discoveredAssets = snap.DiscoveredAssets
	}
	s.nextAssetID = snap.NextAssetID
	for _, d := range snap.Documents {
		if s.documents[d.Kind] == nil {
			s.documents[d.Kind] = make(map[string]model.Document)
		}
		s.documents[d.Kind][d.ID] = d
	}
	return s, nil
}

// persist must be called with s.mu held.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	groupNames := make([]string, 0, len(s.groups))
	for g := range s.groups {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames)
	snap := snapshot{
		Hosts: s.hosts, Facts: s.facts, Changes: s.changes,
		Actions: s.actions, NextActionID: s.nextActionID, Groups: groupNames,
		AuditLog: s.auditLog, NextAuditID: s.nextAuditID,
		APIKeys: s.apiKeys, NextKeyID: s.nextKeyID,
		Rules: s.rules, NextRuleID: s.nextRuleID,
		Enrollments: s.enrollments, NextEnrollID: s.nextEnrollID,
		SoftwareRules: s.softwareRules, NextSoftwareID: s.nextSoftwareID,
		DiscoveredAssets: s.discoveredAssets, NextAssetID: s.nextAssetID,
		Documents: s.documentList(),
	}
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
	if group != "" {
		s.groups[group] = true
	}
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

// QueueAction appends a new action for host, deliberately not
// validating verb/arg -- internal/remediate owns that allow-list, this
// layer just persists whatever it's handed.
func (s *Store) QueueAction(_ context.Context, host, verb, arg string) (model.Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[host]; !ok {
		return model.Action{}, store.ErrHostNotFound
	}
	s.nextActionID++
	a := model.Action{
		ID:       fmt.Sprintf("a%d", s.nextActionID),
		Host:     host,
		Verb:     verb,
		Arg:      arg,
		QueuedAt: time.Now().UTC(),
	}
	s.actions = append(s.actions, a)
	if err := s.persist(); err != nil {
		return model.Action{}, err
	}
	return a, nil
}

// PendingAction returns the oldest not-yet-delivered action for host, in
// queue order (actions is append-only, so index order is queue order).
func (s *Store) PendingAction(_ context.Context, host string) (model.Action, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.actions {
		if a.Host == host && !a.Delivered {
			return a, true, nil
		}
	}
	return model.Action{}, false, nil
}

func (s *Store) MarkActionDelivered(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.actions {
		if s.actions[i].ID == id {
			s.actions[i].Delivered = true
			s.actions[i].DeliveredAt = time.Now().UTC()
			return s.persist()
		}
	}
	return store.ErrActionNotFound
}

func (s *Store) RecordActionResult(_ context.Context, id, status, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.actions {
		if s.actions[i].ID == id {
			s.actions[i].Status = status
			s.actions[i].Detail = detail
			s.actions[i].ReportedAt = time.Now().UTC()
			return s.persist()
		}
	}
	return store.ErrActionNotFound
}

// ListActions returns host's actions, newest first.
func (s *Store) ListActions(_ context.Context, host string) ([]model.Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.Action{}
	for _, a := range s.actions {
		if a.Host == host {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QueuedAt.After(out[j].QueuedAt) })
	return out, nil
}

// ListGroups returns every known board-column name, sorted.
func (s *Store) ListGroups(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.groups))
	for g := range s.groups {
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}

// CreateGroup registers name as a known board column. Idempotent.
func (s *Store) CreateGroup(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.groups[name] {
		return nil
	}
	s.groups[name] = true
	return s.persist()
}

// RecordAudit appends a new audit-log entry.
func (s *Store) RecordAudit(_ context.Context, actor, action, target, detail string) (model.AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAuditID++
	e := model.AuditEntry{
		ID:        fmt.Sprintf("au%d", s.nextAuditID),
		Actor:     actor,
		Action:    action,
		Target:    target,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	}
	s.auditLog = append(s.auditLog, e)
	if err := s.persist(); err != nil {
		return model.AuditEntry{}, err
	}
	return e, nil
}

// ListAudit returns audit entries newest first, optionally filtered to
// one host, capped at limit (<= 0 means unbounded).
func (s *Store) ListAudit(_ context.Context, host string, limit int) ([]model.AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.AuditEntry{}
	for _, e := range s.auditLog {
		if host == "" || e.Target == host {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CreateAPIKey persists a new named, role-scoped credential.
func (s *Store) CreateAPIKey(_ context.Context, name, role, group, tokenHash string) (model.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextKeyID++
	k := model.APIKey{
		ID:        fmt.Sprintf("k%d", s.nextKeyID),
		Name:      name,
		Role:      role,
		Group:     group,
		TokenHash: tokenHash,
		CreatedAt: time.Now().UTC(),
	}
	s.apiKeys = append(s.apiKeys, k)
	if err := s.persist(); err != nil {
		return model.APIKey{}, err
	}
	return k, nil
}

// ListAPIKeys returns every key, sorted by name.
func (s *Store) ListAPIKeys(_ context.Context) ([]model.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.APIKey, len(s.apiKeys))
	copy(out, s.apiKeys)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// FindAPIKeyByHash looks up a key by its token's hash.
func (s *Store) FindAPIKeyByHash(_ context.Context, tokenHash string) (model.APIKey, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.apiKeys {
		if k.TokenHash == tokenHash {
			return k, true, nil
		}
	}
	return model.APIKey{}, false, nil
}

// DeleteAPIKey removes a key by ID.
func (s *Store) DeleteAPIKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.apiKeys {
		if k.ID == id {
			s.apiKeys = append(s.apiKeys[:i:i], s.apiKeys[i+1:]...)
			return s.persist()
		}
	}
	return store.ErrAPIKeyNotFound
}

// CreateRule persists a new policy rule.
func (s *Store) CreateRule(_ context.Context, rule model.Rule) (model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextRuleID++
	rule.ID = fmt.Sprintf("r%d", s.nextRuleID)
	rule.CreatedAt = time.Now().UTC()
	s.rules = append(s.rules, rule)
	if err := s.persist(); err != nil {
		return model.Rule{}, err
	}
	return rule, nil
}

// ListRules returns every rule, in creation order.
func (s *Store) ListRules(_ context.Context) ([]model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Rule, len(s.rules))
	copy(out, s.rules)
	return out, nil
}

// DeleteRule removes a rule by ID.
func (s *Store) DeleteRule(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rules {
		if r.ID == id {
			s.rules = append(s.rules[:i:i], s.rules[i+1:]...)
			return s.persist()
		}
	}
	return store.ErrRuleNotFound
}

// CreateSoftwareRule persists a new software allow/deny rule.
func (s *Store) CreateSoftwareRule(_ context.Context, rule model.SoftwareRule) (model.SoftwareRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSoftwareID++
	rule.ID = fmt.Sprintf("sw%d", s.nextSoftwareID)
	rule.CreatedAt = time.Now().UTC()
	s.softwareRules = append(s.softwareRules, rule)
	if err := s.persist(); err != nil {
		return model.SoftwareRule{}, err
	}
	return rule, nil
}

// ListSoftwareRules returns every software rule, in creation order.
func (s *Store) ListSoftwareRules(_ context.Context) ([]model.SoftwareRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.SoftwareRule, len(s.softwareRules))
	copy(out, s.softwareRules)
	return out, nil
}

// DeleteSoftwareRule removes a software rule by ID.
func (s *Store) DeleteSoftwareRule(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.softwareRules {
		if r.ID == id {
			s.softwareRules = append(s.softwareRules[:i:i], s.softwareRules[i+1:]...)
			return s.persist()
		}
	}
	return store.ErrSoftwareRuleNotFound
}

// CreateEnrollment persists a new pending enrollment for host.
func (s *Store) CreateEnrollment(_ context.Context, host, platform, tokenHash string) (model.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextEnrollID++
	e := model.Enrollment{
		ID:        fmt.Sprintf("e%d", s.nextEnrollID),
		Host:      host,
		Platform:  platform,
		TokenHash: tokenHash,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}
	s.enrollments = append(s.enrollments, e)
	if err := s.persist(); err != nil {
		return model.Enrollment{}, err
	}
	return e, nil
}

// ListEnrollments returns every enrollment, newest first.
func (s *Store) ListEnrollments(_ context.Context) ([]model.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Enrollment, len(s.enrollments))
	copy(out, s.enrollments)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// FindEnrollmentByHash looks up an enrollment by its token's hash.
func (s *Store) FindEnrollmentByHash(_ context.Context, tokenHash string) (model.Enrollment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.enrollments {
		if e.TokenHash == tokenHash {
			return e, true, nil
		}
	}
	return model.Enrollment{}, false, nil
}

// MarkEnrolled flips an enrollment to "enrolled" and stamps EnrolledAt,
// the first time only.
func (s *Store) MarkEnrolled(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.enrollments {
		if e.ID == id {
			if e.Status == "enrolled" {
				return nil
			}
			s.enrollments[i].Status = "enrolled"
			s.enrollments[i].EnrolledAt = time.Now().UTC()
			return s.persist()
		}
	}
	return store.ErrEnrollmentNotFound
}

// DeleteEnrollment revokes an enrollment by ID.
func (s *Store) DeleteEnrollment(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.enrollments {
		if e.ID == id {
			s.enrollments = append(s.enrollments[:i:i], s.enrollments[i+1:]...)
			return s.persist()
		}
	}
	return store.ErrEnrollmentNotFound
}

// UpsertDiscoveredAsset records or refreshes a discovered asset by
// Address, preserving ID/DiscoveredAt across repeat sightings the same
// way UpsertHost preserves FirstSeen.
func (s *Store) UpsertDiscoveredAsset(_ context.Context, asset model.DiscoveredAsset) (model.DiscoveredAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	asset.LastSeenAt = now
	for i, existing := range s.discoveredAssets {
		if existing.Address == asset.Address {
			asset.ID = existing.ID
			asset.DiscoveredAt = existing.DiscoveredAt
			s.discoveredAssets[i] = asset
			if err := s.persist(); err != nil {
				return model.DiscoveredAsset{}, err
			}
			return asset, nil
		}
	}
	s.nextAssetID++
	asset.ID = fmt.Sprintf("asset%d", s.nextAssetID)
	asset.DiscoveredAt = now
	s.discoveredAssets = append(s.discoveredAssets, asset)
	if err := s.persist(); err != nil {
		return model.DiscoveredAsset{}, err
	}
	return asset, nil
}

// ListDiscoveredAssets returns every discovered asset, most recently
// seen first.
func (s *Store) ListDiscoveredAssets(_ context.Context) ([]model.DiscoveredAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.DiscoveredAsset, len(s.discoveredAssets))
	copy(out, s.discoveredAssets)
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

// DeleteDiscoveredAsset removes a discovered asset by ID.
func (s *Store) DeleteDiscoveredAsset(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.discoveredAssets {
		if a.ID == id {
			s.discoveredAssets = append(s.discoveredAssets[:i:i], s.discoveredAssets[i+1:]...)
			return s.persist()
		}
	}
	return store.ErrDiscoveredAssetNotFound
}

// documentList flattens the documents map for the snapshot, in a stable
// (kind, id) order so the JSON file diffs cleanly. Must be called with
// s.mu held.
func (s *Store) documentList() []model.Document {
	var out []model.Document
	for _, byID := range s.documents {
		for _, d := range byID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// PutDocument creates or replaces the document keyed by (Kind, ID).
func (s *Store) PutDocument(_ context.Context, doc model.Document) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.documents[doc.Kind] == nil {
		s.documents[doc.Kind] = make(map[string]model.Document)
	}
	doc.UpdatedAt = time.Now().UTC()
	s.documents[doc.Kind][doc.ID] = doc
	return s.persist()
}

// GetDocument returns the document keyed by (kind, id), if any.
func (s *Store) GetDocument(_ context.Context, kind, id string) (model.Document, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.documents[kind][id]
	return d, ok, nil
}

// ListDocuments returns every document of one kind, sorted by ID.
func (s *Store) ListDocuments(_ context.Context, kind string) ([]model.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Document, 0, len(s.documents[kind]))
	for _, d := range s.documents[kind] {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteDocument removes one document by (kind, id).
func (s *Store) DeleteDocument(_ context.Context, kind, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.documents[kind][id]; !ok {
		return store.ErrDocumentNotFound
	}
	delete(s.documents[kind], id)
	return s.persist()
}

// compile-time check that Store satisfies store.Store.
var _ store.Store = (*Store)(nil)
