/*******************************************************************************
 * @file         store.go
 * @brief        Package store defines the persistence contract every backend (in-memory, Postgres, whatever comes next) implements.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package store defines the persistence contract every backend (in-memory,
// Postgres, whatever comes next) implements. Everything above this layer
// -- the cook pipeline, the API -- only ever talks to the Store interface,
// so swapping the backend later (the natural next step: Postgres, per
// the earlier InfraAtlas-next design) touches one implementation, not
// every caller.
package store

import (
	"context"
	"errors"

	"muster/internal/model"
)

// Store is the full persistence contract. UpsertFact is expected to
// diff the incoming data against whatever was previously stored for
// (host, category) and record the result via RecordChanges -- see
// memstore for the reference implementation of that behavior.
type Store interface {
	UpsertHost(ctx context.Context, host model.Host) error
	GetHost(ctx context.Context, name string) (model.Host, bool, error)
	ListHosts(ctx context.Context) ([]model.Host, error)

	// SetHostGroup and SetHostTags are operator-driven metadata writes
	// (the Kanban board and its tag labels), deliberately kept separate
	// from UpsertHost: UpsertHost is the cook pipeline's identity/
	// last-seen write and never touches Group/Tags, so a re-cook can
	// never clobber board placement. Both return ErrHostNotFound if the
	// host doesn't exist yet -- assign a group only to a host that has
	// already reported in at least once.
	SetHostGroup(ctx context.Context, name, group string) (model.Host, error)
	SetHostTags(ctx context.Context, name string, tags []string) (model.Host, error)

	UpsertFact(ctx context.Context, fact model.Fact) ([]model.Change, error)
	GetFact(ctx context.Context, host, category string) (model.Fact, bool, error)
	ListFacts(ctx context.Context, host string) ([]model.Fact, error)

	// ListChanges returns a host's recorded field changes, newest
	// first, capped at limit (0 or negative means "no cap").
	ListChanges(ctx context.Context, host string, limit int) ([]model.Change, error)

	// Query does a simple substring match against a category's data,
	// across all hosts -- enough to answer the kind of question the
	// original project's docs call out as the whole point: "which
	// servers are running version X of a package."
	Query(ctx context.Context, category, field, contains string) ([]model.Fact, error)

	// QueueAction records a new remediation action for host, to be
	// handed to that host's agent the next time it reports in. Verb/Arg
	// are not validated here -- internal/remediate owns the allow-list;
	// Store just persists what it's given. Returns ErrHostNotFound if
	// host has never reported in.
	QueueAction(ctx context.Context, host, verb, arg string) (model.Action, error)

	// PendingAction returns the oldest not-yet-delivered action queued
	// for host, if any.
	PendingAction(ctx context.Context, host string) (model.Action, bool, error)

	// MarkActionDelivered records that a queued action was handed to its
	// host's agent -- called the moment the ingest daemon writes it into
	// a reply, before it knows whether the agent will ever execute it or
	// report a result back.
	MarkActionDelivered(ctx context.Context, id string) error

	// RecordActionResult records what happened when an agent executed a
	// delivered action. status is "ok" or "fail"; detail is short free
	// text, never trusted as anything but a log line.
	RecordActionResult(ctx context.Context, id, status, detail string) error

	// ListActions returns a host's actions, newest first.
	ListActions(ctx context.Context, host string) ([]model.Action, error)

	// ListGroups returns every known board-column name, sorted --
	// both ones explicitly created via CreateGroup and any that exist
	// only because a host's group was set to them (SetHostGroup
	// registers the name here too, so this is always a superset of
	// "groups at least one host is currently in"). Lets the web UI's
	// board render an empty column an operator created but hasn't
	// dropped a host into yet, and have it survive a reload.
	ListGroups(ctx context.Context) ([]string, error)

	// CreateGroup registers a board-column name with no host in it yet.
	// Idempotent -- creating a name that already exists (whether via an
	// earlier CreateGroup or because some host already has that group)
	// is a no-op success, not an error.
	CreateGroup(ctx context.Context, name string) error

	// RecordAudit appends one audit-log entry. Never returns
	// ErrHostNotFound or similar -- an audit entry is a record of what
	// happened, not a validated reference to a host, so a typo'd or
	// stale Target still gets logged rather than silently dropped.
	RecordAudit(ctx context.Context, actor, action, target, detail string) (model.AuditEntry, error)

	// ListAudit returns audit entries newest first, capped at limit
	// (<= 0 means unbounded). If host is non-empty, only entries whose
	// Target equals host are returned.
	ListAudit(ctx context.Context, host string, limit int) ([]model.AuditEntry, error)

	// CreateAPIKey persists a new named, role-scoped credential,
	// optionally scoped to one board group (see model.APIKey.Group).
	// tokenHash is a SHA-256 hex digest computed by the caller
	// (internal/api) -- Store never sees or stores the raw token.
	CreateAPIKey(ctx context.Context, name, role, group, tokenHash string) (model.APIKey, error)

	// ListAPIKeys returns every key, sorted by name. TokenHash is
	// included (Store's own record), but model.APIKey never marshals it
	// to JSON (see its `json:"-"` tag) -- the API layer is what actually
	// enforces "never expose this."
	ListAPIKeys(ctx context.Context) ([]model.APIKey, error)

	// FindAPIKeyByHash looks up a key by its token's SHA-256 hash --
	// the only way a raw bearer token is ever resolved to a role.
	FindAPIKeyByHash(ctx context.Context, tokenHash string) (model.APIKey, bool, error)

	// DeleteAPIKey removes a key by ID. Returns ErrAPIKeyNotFound if no
	// such key exists.
	DeleteAPIKey(ctx context.Context, id string) error

	// CreateRule persists a new policy rule. ID/CreatedAt in the passed
	// Rule are ignored and assigned by the store.
	CreateRule(ctx context.Context, rule model.Rule) (model.Rule, error)

	// ListRules returns every rule, in creation order.
	ListRules(ctx context.Context) ([]model.Rule, error)

	// DeleteRule removes a rule by ID. Returns ErrRuleNotFound if no
	// such rule exists.
	DeleteRule(ctx context.Context, id string) error

	// CreateSoftwareRule persists a new software allow/deny rule.
	// ID/CreatedAt in the passed SoftwareRule are ignored and assigned
	// by the store.
	CreateSoftwareRule(ctx context.Context, rule model.SoftwareRule) (model.SoftwareRule, error)

	// ListSoftwareRules returns every software rule, in creation order.
	ListSoftwareRules(ctx context.Context) ([]model.SoftwareRule, error)

	// DeleteSoftwareRule removes a software rule by ID. Returns
	// ErrSoftwareRuleNotFound if no such rule exists.
	DeleteSoftwareRule(ctx context.Context, id string) error

	// CreateEnrollment persists a new pending enrollment for host.
	// tokenHash is the SHA-256 hash of the raw enrollment token -- the
	// store never sees or stores the raw value, same discipline as
	// CreateAPIKey.
	CreateEnrollment(ctx context.Context, host, platform, tokenHash string) (model.Enrollment, error)

	// ListEnrollments returns every enrollment, newest first.
	ListEnrollments(ctx context.Context) ([]model.Enrollment, error)

	// FindEnrollmentByHash looks up an enrollment by its token's hash,
	// regardless of Status -- callers (internal/ingest, internal/api's
	// mobile report handler) decide what a "pending" vs "enrolled" match
	// means for the request in front of them.
	FindEnrollmentByHash(ctx context.Context, tokenHash string) (model.Enrollment, bool, error)

	// MarkEnrolled flips an enrollment's Status to "enrolled" and stamps
	// EnrolledAt, the first time (and only the first time) its token
	// successfully authenticates a report. A no-op if it's already
	// enrolled -- callers don't need to check Status before calling this.
	MarkEnrolled(ctx context.Context, id string) error

	// DeleteEnrollment revokes an enrollment by ID -- any request still
	// presenting its token fails its next auth check immediately.
	// Returns ErrEnrollmentNotFound if no such enrollment exists.
	DeleteEnrollment(ctx context.Context, id string) error

	// UpsertDiscoveredAsset records or refreshes one asset found by a
	// network discovery scan, keyed by Address: a repeat sighting updates
	// OpenPorts/Banners/ScannedBy/ScannedCIDR/Known/LastSeenAt in place
	// and leaves ID/DiscoveredAt untouched, the same "first-seen is
	// sticky" shape UpsertHost already uses for Host/FirstSeen.
	UpsertDiscoveredAsset(ctx context.Context, asset model.DiscoveredAsset) (model.DiscoveredAsset, error)

	// ListDiscoveredAssets returns every discovered asset, most recently
	// seen first.
	ListDiscoveredAssets(ctx context.Context) ([]model.DiscoveredAsset, error)

	// DeleteDiscoveredAsset removes a discovered asset by ID -- e.g. once
	// an operator has onboarded it as a real managed Host and the
	// sighting is no longer useful. Returns ErrDiscoveredAssetNotFound if
	// no such asset exists.
	DeleteDiscoveredAsset(ctx context.Context, id string) error

	// PutDocument creates or replaces the model.Document keyed by
	// (Kind, ID) -- see model.Document for what belongs here and what
	// doesn't. UpdatedAt is stamped by the store.
	PutDocument(ctx context.Context, doc model.Document) error

	// GetDocument returns the document keyed by (kind, id), if any.
	GetDocument(ctx context.Context, kind, id string) (model.Document, bool, error)

	// ListDocuments returns every document of one kind, sorted by ID.
	ListDocuments(ctx context.Context, kind string) ([]model.Document, error)

	// DeleteDocument removes one document. Returns ErrDocumentNotFound
	// if there is no such (kind, id).
	DeleteDocument(ctx context.Context, kind, id string) error
}

// ErrHostNotFound is returned by SetHostGroup/SetHostTags (and may be
// used by future host-scoped writes) when the named host has no record
// yet -- distinguished from other errors so the API layer can answer
// with 404 instead of 500.
var ErrHostNotFound = errors.New("store: host not found")

// ErrActionNotFound is returned by MarkActionDelivered/RecordActionResult
// when no action with the given id exists.
var ErrActionNotFound = errors.New("store: action not found")

// ErrAPIKeyNotFound is returned by DeleteAPIKey when no key with the
// given id exists.
var ErrAPIKeyNotFound = errors.New("store: api key not found")

// ErrRuleNotFound is returned by DeleteRule when no rule with the given
// id exists.
var ErrRuleNotFound = errors.New("store: rule not found")

// ErrSoftwareRuleNotFound is returned by DeleteSoftwareRule when no
// software rule with the given id exists.
var ErrSoftwareRuleNotFound = errors.New("store: software rule not found")

// ErrEnrollmentNotFound is returned by DeleteEnrollment when no
// enrollment with the given id exists.
var ErrEnrollmentNotFound = errors.New("store: enrollment not found")

// ErrDiscoveredAssetNotFound is returned by DeleteDiscoveredAsset when
// no discovered asset with the given id exists.
var ErrDiscoveredAssetNotFound = errors.New("store: discovered asset not found")

// ErrDocumentNotFound is returned by DeleteDocument when no document with
// the given (kind, id) exists.
var ErrDocumentNotFound = errors.New("store: document not found")
