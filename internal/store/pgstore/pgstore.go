// Package pgstore is a Postgres-backed implementation of store.Store.
//
// memstore proves the interface; this is what a real deployment wants --
// facts survive a restart without a JSON-snapshot file, more than one
// muster process can share a database, and "which hosts run Ubuntu"
// becomes a query Postgres can index instead of a full in-memory scan.
// Nothing above the Store interface (internal/cook, internal/api) changes
// at all to use it -- that's the point of the interface.
package pgstore

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq" // registers the "postgres" database/sql driver; pq.Array wraps []string for the tags column

	"muster/internal/model"
	"muster/internal/store"
)

//go:embed schema.sql
var schemaSQL string

// Store is a Postgres-backed store.Store. It owns a *sql.DB (itself a
// connection pool -- Store is safe for concurrent use the same way
// database/sql is).
type Store struct {
	db *sql.DB
}

// New opens a connection to Postgres at dsn (a standard
// "postgres://user:pass@host:port/dbname?sslmode=..." URL, or any DSN
// lib/pq accepts), verifies it with a ping, and applies the schema
// (CREATE TABLE/INDEX IF NOT EXISTS -- safe to run on every startup).
func New(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: opening connection: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgstore: connecting: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgstore: applying schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() error {
	return s.db.Close()
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func (s *Store) UpsertHost(ctx context.Context, host model.Host) error {
	if host.FirstSeen.IsZero() {
		host.FirstSeen = time.Now().UTC()
	}
	// On conflict, first_seen is deliberately left out of the SET list:
	// Postgres keeps the row's original value, giving the same "first
	// seen sticks, everything else refreshes" behavior as memstore
	// without a separate read-then-write round trip.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hosts (name, platform, first_seen, last_cooked)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO UPDATE SET
			platform    = EXCLUDED.platform,
			last_cooked = EXCLUDED.last_cooked
	`, host.Name, host.Platform, host.FirstSeen, nullableTime(host.LastCooked))
	if err != nil {
		return fmt.Errorf("pgstore: upserting host %q: %w", host.Name, err)
	}
	return nil
}

const hostColumns = `name, platform, first_seen, last_cooked, group_name, tags`

func scanHost(row interface{ Scan(...any) error }) (model.Host, error) {
	var h model.Host
	var lastCooked sql.NullTime
	if err := row.Scan(&h.Name, &h.Platform, &h.FirstSeen, &lastCooked, &h.Group, pq.Array(&h.Tags)); err != nil {
		return model.Host{}, err
	}
	if lastCooked.Valid {
		h.LastCooked = lastCooked.Time
	}
	if len(h.Tags) == 0 {
		h.Tags = nil // matches the JSON `omitempty` -- an empty {} array reads back as "no tags", not []
	}
	return h, nil
}

func (s *Store) GetHost(ctx context.Context, name string) (model.Host, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+hostColumns+` FROM hosts WHERE name = $1`, name)
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Host{}, false, nil
	}
	if err != nil {
		return model.Host{}, false, fmt.Errorf("pgstore: getting host %q: %w", name, err)
	}
	return h, true, nil
}

func (s *Store) ListHosts(ctx context.Context) ([]model.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostColumns+` FROM hosts ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing hosts: %w", err)
	}
	defer rows.Close()

	out := []model.Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning host: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetHostGroup assigns the host to a board column (empty string means
// "Ungrouped"). Group/tags are never touched by UpsertHost -- see the
// column comments in schema.sql -- so this is the only writer.
func (s *Store) SetHostGroup(ctx context.Context, name, group string) (model.Host, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE hosts SET group_name = $2 WHERE name = $1
		RETURNING `+hostColumns, name, group)
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Host{}, store.ErrHostNotFound
	}
	if err != nil {
		return model.Host{}, fmt.Errorf("pgstore: setting group for %q: %w", name, err)
	}
	return h, nil
}

func (s *Store) SetHostTags(ctx context.Context, name string, tags []string) (model.Host, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE hosts SET tags = $2 WHERE name = $1
		RETURNING `+hostColumns, name, pq.Array(tags))
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Host{}, store.ErrHostNotFound
	}
	if err != nil {
		return model.Host{}, fmt.Errorf("pgstore: setting tags for %q: %w", name, err)
	}
	return h, nil
}

// UpsertFact stores fact, diffing it against whatever was previously
// stored for (fact.Host, fact.Category) and recording the result to the
// changes table -- all inside one transaction, with the previous row
// locked FOR UPDATE, so two concurrent reports for the same host/category
// can't both diff against the same "previous" value and double-count (or
// drop) a change.
func (s *Store) UpsertFact(ctx context.Context, fact model.Fact) ([]model.Change, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("pgstore: beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	var changes []model.Change
	var prevRaw []byte
	err = tx.QueryRowContext(ctx, `
		SELECT data FROM facts WHERE host = $1 AND category = $2 FOR UPDATE
	`, fact.Host, fact.Category).Scan(&prevRaw)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		// First report for this host/category -- nothing to diff against.
	case err != nil:
		return nil, fmt.Errorf("pgstore: reading previous fact: %w", err)
	default:
		var prevData map[string]any
		if err := json.Unmarshal(prevRaw, &prevData); err != nil {
			return nil, fmt.Errorf("pgstore: decoding stored fact data: %w", err)
		}
		changes = store.Diff(fact.Host, fact.Category, prevData, fact.Data)
		changes = store.WithTimestamp(changes, fact.CookedAt)
	}

	newRaw, err := json.Marshal(fact.Data)
	if err != nil {
		return nil, fmt.Errorf("pgstore: encoding fact data: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO facts (host, category, data, cooked_at)
		VALUES ($1, $2, $3::jsonb, $4)
		ON CONFLICT (host, category) DO UPDATE SET
			data      = EXCLUDED.data,
			cooked_at = EXCLUDED.cooked_at
	`, fact.Host, fact.Category, newRaw, nullableTime(fact.CookedAt)); err != nil {
		return nil, fmt.Errorf("pgstore: upserting fact: %w", err)
	}

	for _, c := range changes {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO changes (host, category, field, old_value, new_value, action, changed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, c.Host, c.Category, c.Field, c.OldValue, c.NewValue, c.Action, c.ChangedAt); err != nil {
			return nil, fmt.Errorf("pgstore: recording change: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("pgstore: committing: %w", err)
	}
	return changes, nil
}

func (s *Store) GetFact(ctx context.Context, host, category string) (model.Fact, bool, error) {
	var f model.Fact
	var raw []byte
	var cookedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT host, category, data, cooked_at FROM facts WHERE host = $1 AND category = $2
	`, host, category).Scan(&f.Host, &f.Category, &raw, &cookedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Fact{}, false, nil
	}
	if err != nil {
		return model.Fact{}, false, fmt.Errorf("pgstore: getting fact: %w", err)
	}
	if err := json.Unmarshal(raw, &f.Data); err != nil {
		return model.Fact{}, false, fmt.Errorf("pgstore: decoding fact data: %w", err)
	}
	if cookedAt.Valid {
		f.CookedAt = cookedAt.Time
	}
	return f, true, nil
}

func (s *Store) ListFacts(ctx context.Context, host string) ([]model.Fact, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, category, data, cooked_at FROM facts WHERE host = $1 ORDER BY category
	`, host)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing facts for %q: %w", host, err)
	}
	defer rows.Close()

	out := []model.Fact{}
	for rows.Next() {
		var f model.Fact
		var raw []byte
		var cookedAt sql.NullTime
		if err := rows.Scan(&f.Host, &f.Category, &raw, &cookedAt); err != nil {
			return nil, fmt.Errorf("pgstore: scanning fact: %w", err)
		}
		if err := json.Unmarshal(raw, &f.Data); err != nil {
			return nil, fmt.Errorf("pgstore: decoding fact data: %w", err)
		}
		if cookedAt.Valid {
			f.CookedAt = cookedAt.Time
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out, rows.Err()
}

// ListChanges returns host's recorded changes, newest first, capped at
// limit (<= 0 means unbounded).
func (s *Store) ListChanges(ctx context.Context, host string, limit int) ([]model.Change, error) {
	query := `
		SELECT host, category, field, old_value, new_value, action, changed_at
		FROM changes WHERE host = $1 ORDER BY changed_at DESC`
	args := []any{host}
	if limit > 0 {
		query += ` LIMIT $2`
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing changes for %q: %w", host, err)
	}
	defer rows.Close()

	out := []model.Change{}
	for rows.Next() {
		var c model.Change
		if err := rows.Scan(&c.Host, &c.Category, &c.Field, &c.OldValue, &c.NewValue, &c.Action, &c.ChangedAt); err != nil {
			return nil, fmt.Errorf("pgstore: scanning change: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// likeEscaper escapes LIKE/ILIKE metacharacters so Query's `contains` is
// matched as a literal substring, same as memstore's strings.Contains --
// not as a glob pattern.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (s *Store) Query(ctx context.Context, category, field, contains string) ([]model.Fact, error) {
	pattern := "%" + likeEscaper.Replace(contains) + "%"
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, category, data, cooked_at
		FROM facts
		WHERE category = $1 AND data ->> $2 ILIKE $3 ESCAPE '\'
		ORDER BY host
	`, category, field, pattern)
	if err != nil {
		return nil, fmt.Errorf("pgstore: querying: %w", err)
	}
	defer rows.Close()

	out := []model.Fact{}
	for rows.Next() {
		var f model.Fact
		var raw []byte
		var cookedAt sql.NullTime
		if err := rows.Scan(&f.Host, &f.Category, &raw, &cookedAt); err != nil {
			return nil, fmt.Errorf("pgstore: scanning query result: %w", err)
		}
		if err := json.Unmarshal(raw, &f.Data); err != nil {
			return nil, fmt.Errorf("pgstore: decoding fact data: %w", err)
		}
		if cookedAt.Valid {
			f.CookedAt = cookedAt.Time
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// compile-time check that Store satisfies store.Store.
var _ store.Store = (*Store)(nil)
