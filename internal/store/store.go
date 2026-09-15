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
}

// ErrHostNotFound is returned by SetHostGroup/SetHostTags (and may be
// used by future host-scoped writes) when the named host has no record
// yet -- distinguished from other errors so the API layer can answer
// with 404 instead of 500.
var ErrHostNotFound = errors.New("store: host not found")
