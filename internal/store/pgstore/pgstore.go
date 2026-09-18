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
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq" // registers the "postgres" database/sql driver; pq.Array wraps []string for the tags column

	"muster/internal/model"
	"muster/internal/store"
)

// Store is a Postgres-backed store.Store. It owns a *sql.DB (itself a
// connection pool -- Store is safe for concurrent use the same way
// database/sql is).
type Store struct {
	db *sql.DB
}

// New opens a connection to Postgres at dsn (a standard
// "postgres://user:pass@host:port/dbname?sslmode=..." URL, or any DSN
// lib/pq accepts), verifies it with a ping, and brings the schema up to
// date by applying any embedded migrations/*.sql file not yet recorded
// in schema_migrations (see migrate.go) -- safe to run on every startup,
// whether the database is brand new, already up to date, or predates
// the migration runner entirely.
func New(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: opening connection: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgstore: connecting: %w", err)
	}
	if err := applyMigrations(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgstore: applying migrations: %w", err)
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
// column comments in migrations/0001_init.sql -- so this is the only writer.
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
	if group != "" {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO groups (name) VALUES ($1) ON CONFLICT DO NOTHING`, group); err != nil {
			return model.Host{}, fmt.Errorf("pgstore: registering group %q: %w", group, err)
		}
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

const actionColumns = `id, host, verb, arg, queued_at, delivered, delivered_at, status, detail, reported_at`

func scanAction(row interface{ Scan(...any) error }) (model.Action, error) {
	var a model.Action
	var id int64
	var deliveredAt, reportedAt sql.NullTime
	if err := row.Scan(&id, &a.Host, &a.Verb, &a.Arg, &a.QueuedAt, &a.Delivered, &deliveredAt, &a.Status, &a.Detail, &reportedAt); err != nil {
		return model.Action{}, err
	}
	a.ID = strconv.FormatInt(id, 10)
	if deliveredAt.Valid {
		a.DeliveredAt = deliveredAt.Time
	}
	if reportedAt.Valid {
		a.ReportedAt = reportedAt.Time
	}
	return a, nil
}

// QueueAction inserts a new action row for host, guarded by the same
// EXISTS check GetHost effectively does elsewhere, in one round trip:
// no row is inserted at all if host has never reported in, and the
// caller gets back store.ErrHostNotFound exactly like an UPDATE ...
// RETURNING against a missing host does elsewhere in this file.
func (s *Store) QueueAction(ctx context.Context, host, verb, arg string) (model.Action, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO actions (host, verb, arg, queued_at)
		SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM hosts WHERE name = $1)
		RETURNING `+actionColumns, host, verb, arg, time.Now().UTC())
	a, err := scanAction(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Action{}, store.ErrHostNotFound
	}
	if err != nil {
		return model.Action{}, fmt.Errorf("pgstore: queuing action for %q: %w", host, err)
	}
	return a, nil
}

func (s *Store) PendingAction(ctx context.Context, host string) (model.Action, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+actionColumns+` FROM actions
		WHERE host = $1 AND delivered = FALSE
		ORDER BY queued_at ASC LIMIT 1`, host)
	a, err := scanAction(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Action{}, false, nil
	}
	if err != nil {
		return model.Action{}, false, fmt.Errorf("pgstore: getting pending action for %q: %w", host, err)
	}
	return a, true, nil
}

// actionRowID parses the opaque string id this package itself always
// hands out (strconv.FormatInt of the bigserial) back into the int64
// actions.id is stored as. A ParseInt failure just means "not one of
// ours" -- treated the same as a real id that doesn't match any row.
func actionRowID(id string) (int64, bool) {
	n, err := strconv.ParseInt(id, 10, 64)
	return n, err == nil
}

func (s *Store) MarkActionDelivered(ctx context.Context, id string) error {
	n, ok := actionRowID(id)
	if !ok {
		return store.ErrActionNotFound
	}
	res, err := s.db.ExecContext(ctx, `UPDATE actions SET delivered = TRUE, delivered_at = $2 WHERE id = $1`, n, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("pgstore: marking action %s delivered: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrActionNotFound
	}
	return nil
}

func (s *Store) RecordActionResult(ctx context.Context, id, status, detail string) error {
	n, ok := actionRowID(id)
	if !ok {
		return store.ErrActionNotFound
	}
	res, err := s.db.ExecContext(ctx, `UPDATE actions SET status = $2, detail = $3, reported_at = $4 WHERE id = $1`, n, status, detail, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("pgstore: recording result for action %s: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrActionNotFound
	}
	return nil
}

// ListActions returns host's actions, newest first.
func (s *Store) ListActions(ctx context.Context, host string) ([]model.Action, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+actionColumns+` FROM actions WHERE host = $1 ORDER BY queued_at DESC`, host)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing actions for %q: %w", host, err)
	}
	defer rows.Close()

	out := []model.Action{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListGroups returns every known board-column name, sorted.
func (s *Store) ListGroups(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing groups: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("pgstore: scanning group: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// CreateGroup registers name as a known board column. Idempotent.
func (s *Store) CreateGroup(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO groups (name) VALUES ($1) ON CONFLICT DO NOTHING`, name)
	if err != nil {
		return fmt.Errorf("pgstore: creating group %q: %w", name, err)
	}
	return nil
}

const auditColumns = `id, actor, action, target, detail, created_at`

func scanAudit(row interface{ Scan(...any) error }) (model.AuditEntry, error) {
	var e model.AuditEntry
	var id int64
	if err := row.Scan(&id, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.CreatedAt); err != nil {
		return model.AuditEntry{}, err
	}
	e.ID = strconv.FormatInt(id, 10)
	return e, nil
}

// RecordAudit inserts a new audit-log entry.
func (s *Store) RecordAudit(ctx context.Context, actor, action, target, detail string) (model.AuditEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO audit_log (actor, action, target, detail, created_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+auditColumns, actor, action, target, detail, time.Now().UTC())
	e, err := scanAudit(row)
	if err != nil {
		return model.AuditEntry{}, fmt.Errorf("pgstore: recording audit entry: %w", err)
	}
	return e, nil
}

// ListAudit returns audit entries newest first, optionally filtered to
// one host, capped at limit (<= 0 means unbounded).
func (s *Store) ListAudit(ctx context.Context, host string, limit int) ([]model.AuditEntry, error) {
	query := `SELECT ` + auditColumns + ` FROM audit_log`
	args := []any{}
	if host != "" {
		query += ` WHERE target = $1`
		args = append(args, host)
	}
	query += ` ORDER BY created_at DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing audit entries: %w", err)
	}
	defer rows.Close()

	out := []model.AuditEntry{}
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning audit entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const apiKeyColumns = `id, name, role, token_hash, created_at`

func scanAPIKey(row interface{ Scan(...any) error }) (model.APIKey, error) {
	var k model.APIKey
	var id int64
	if err := row.Scan(&id, &k.Name, &k.Role, &k.TokenHash, &k.CreatedAt); err != nil {
		return model.APIKey{}, err
	}
	k.ID = strconv.FormatInt(id, 10)
	return k, nil
}

// CreateAPIKey persists a new named, role-scoped credential.
func (s *Store) CreateAPIKey(ctx context.Context, name, role, tokenHash string) (model.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO api_keys (name, role, token_hash, created_at)
		VALUES ($1, $2, $3, $4)
		RETURNING `+apiKeyColumns, name, role, tokenHash, time.Now().UTC())
	k, err := scanAPIKey(row)
	if err != nil {
		return model.APIKey{}, fmt.Errorf("pgstore: creating api key %q: %w", name, err)
	}
	return k, nil
}

// ListAPIKeys returns every key, sorted by name.
func (s *Store) ListAPIKeys(ctx context.Context) ([]model.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiKeyColumns+` FROM api_keys ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing api keys: %w", err)
	}
	defer rows.Close()

	out := []model.APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning api key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// FindAPIKeyByHash looks up a key by its token's hash.
func (s *Store) FindAPIKeyByHash(ctx context.Context, tokenHash string) (model.APIKey, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+apiKeyColumns+` FROM api_keys WHERE token_hash = $1`, tokenHash)
	k, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIKey{}, false, nil
	}
	if err != nil {
		return model.APIKey{}, false, fmt.Errorf("pgstore: looking up api key: %w", err)
	}
	return k, true, nil
}

// DeleteAPIKey removes a key by ID.
func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	n, ok := actionRowID(id) // same opaque-string-id convention as actions
	if !ok {
		return store.ErrAPIKeyNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = $1`, n)
	if err != nil {
		return fmt.Errorf("pgstore: deleting api key %s: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrAPIKeyNotFound
	}
	return nil
}

const ruleColumns = `id, name, group_name, kind, threshold, category, auto_remediate, auto_remediate_arg, created_at`

func scanRule(row interface{ Scan(...any) error }) (model.Rule, error) {
	var r model.Rule
	var id int64
	if err := row.Scan(&id, &r.Name, &r.Group, &r.Kind, &r.Threshold, &r.Category, &r.AutoRemediate, &r.AutoRemediateArg, &r.CreatedAt); err != nil {
		return model.Rule{}, err
	}
	r.ID = strconv.FormatInt(id, 10)
	return r, nil
}

// CreateRule persists a new policy rule.
func (s *Store) CreateRule(ctx context.Context, rule model.Rule) (model.Rule, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO rules (name, group_name, kind, threshold, category, auto_remediate, auto_remediate_arg, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+ruleColumns,
		rule.Name, rule.Group, rule.Kind, rule.Threshold, rule.Category,
		rule.AutoRemediate, rule.AutoRemediateArg, time.Now().UTC())
	r, err := scanRule(row)
	if err != nil {
		return model.Rule{}, fmt.Errorf("pgstore: creating rule %q: %w", rule.Name, err)
	}
	return r, nil
}

// ListRules returns every rule, in creation order.
func (s *Store) ListRules(ctx context.Context) ([]model.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ruleColumns+` FROM rules ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing rules: %w", err)
	}
	defer rows.Close()

	out := []model.Rule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRule removes a rule by ID.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	n, ok := actionRowID(id)
	if !ok {
		return store.ErrRuleNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = $1`, n)
	if err != nil {
		return fmt.Errorf("pgstore: deleting rule %s: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrRuleNotFound
	}
	return nil
}

const softwareRuleColumns = `id, name, group_name, kind, match, created_at`

func scanSoftwareRule(row interface{ Scan(...any) error }) (model.SoftwareRule, error) {
	var r model.SoftwareRule
	var id int64
	if err := row.Scan(&id, &r.Name, &r.Group, &r.Kind, &r.Match, &r.CreatedAt); err != nil {
		return model.SoftwareRule{}, err
	}
	r.ID = strconv.FormatInt(id, 10)
	return r, nil
}

// CreateSoftwareRule persists a new software allow/deny rule.
func (s *Store) CreateSoftwareRule(ctx context.Context, rule model.SoftwareRule) (model.SoftwareRule, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO software_rules (name, group_name, kind, match, created_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+softwareRuleColumns,
		rule.Name, rule.Group, rule.Kind, rule.Match, time.Now().UTC())
	r, err := scanSoftwareRule(row)
	if err != nil {
		return model.SoftwareRule{}, fmt.Errorf("pgstore: creating software rule %q: %w", rule.Name, err)
	}
	return r, nil
}

// ListSoftwareRules returns every software rule, in creation order.
func (s *Store) ListSoftwareRules(ctx context.Context) ([]model.SoftwareRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+softwareRuleColumns+` FROM software_rules ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing software rules: %w", err)
	}
	defer rows.Close()

	out := []model.SoftwareRule{}
	for rows.Next() {
		r, err := scanSoftwareRule(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning software rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteSoftwareRule removes a software rule by ID.
func (s *Store) DeleteSoftwareRule(ctx context.Context, id string) error {
	n, ok := actionRowID(id)
	if !ok {
		return store.ErrSoftwareRuleNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM software_rules WHERE id = $1`, n)
	if err != nil {
		return fmt.Errorf("pgstore: deleting software rule %s: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrSoftwareRuleNotFound
	}
	return nil
}

const discoveredAssetColumns = `id, address, open_ports, banners, scanned_by, scanned_cidr, known, discovered_at, last_seen_at`

func scanDiscoveredAsset(row interface{ Scan(...any) error }) (model.DiscoveredAsset, error) {
	var a model.DiscoveredAsset
	var id int64
	var ports []int64
	var bannersRaw []byte
	if err := row.Scan(&id, &a.Address, pq.Array(&ports), &bannersRaw, &a.ScannedBy, &a.ScannedCIDR, &a.Known, &a.DiscoveredAt, &a.LastSeenAt); err != nil {
		return model.DiscoveredAsset{}, err
	}
	a.ID = strconv.FormatInt(id, 10)
	a.OpenPorts = make([]int, len(ports))
	for i, p := range ports {
		a.OpenPorts[i] = int(p)
	}
	if len(bannersRaw) > 0 {
		if err := json.Unmarshal(bannersRaw, &a.Banners); err != nil {
			return model.DiscoveredAsset{}, err
		}
	}
	return a, nil
}

// UpsertDiscoveredAsset records or refreshes a discovered asset by
// Address -- ON CONFLICT keeps id/discovered_at from the existing row
// (same "first-seen is sticky" semantics as memstore's implementation)
// and refreshes everything else, including last_seen_at.
func (s *Store) UpsertDiscoveredAsset(ctx context.Context, asset model.DiscoveredAsset) (model.DiscoveredAsset, error) {
	ports := make([]int64, len(asset.OpenPorts))
	for i, p := range asset.OpenPorts {
		ports[i] = int64(p)
	}
	banners := asset.Banners
	if banners == nil {
		banners = map[string]string{}
	}
	bannersRaw, err := json.Marshal(banners)
	if err != nil {
		return model.DiscoveredAsset{}, fmt.Errorf("pgstore: marshaling banners for %q: %w", asset.Address, err)
	}
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO discovered_assets (address, open_ports, banners, scanned_by, scanned_cidr, known, discovered_at, last_seen_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $7)
		ON CONFLICT (address) DO UPDATE SET
			open_ports = EXCLUDED.open_ports,
			banners = EXCLUDED.banners,
			scanned_by = EXCLUDED.scanned_by,
			scanned_cidr = EXCLUDED.scanned_cidr,
			known = EXCLUDED.known,
			last_seen_at = EXCLUDED.last_seen_at
		RETURNING `+discoveredAssetColumns,
		asset.Address, pq.Array(ports), bannersRaw, asset.ScannedBy, asset.ScannedCIDR, asset.Known, now)
	a, err := scanDiscoveredAsset(row)
	if err != nil {
		return model.DiscoveredAsset{}, fmt.Errorf("pgstore: upserting discovered asset %q: %w", asset.Address, err)
	}
	return a, nil
}

// ListDiscoveredAssets returns every discovered asset, most recently
// seen first.
func (s *Store) ListDiscoveredAssets(ctx context.Context) ([]model.DiscoveredAsset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+discoveredAssetColumns+` FROM discovered_assets ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing discovered assets: %w", err)
	}
	defer rows.Close()

	out := []model.DiscoveredAsset{}
	for rows.Next() {
		a, err := scanDiscoveredAsset(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning discovered asset: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteDiscoveredAsset removes a discovered asset by ID.
func (s *Store) DeleteDiscoveredAsset(ctx context.Context, id string) error {
	n, ok := actionRowID(id)
	if !ok {
		return store.ErrDiscoveredAssetNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM discovered_assets WHERE id = $1`, n)
	if err != nil {
		return fmt.Errorf("pgstore: deleting discovered asset %s: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrDiscoveredAssetNotFound
	}
	return nil
}

const enrollmentColumns = `id, host, platform, token_hash, status, created_at, enrolled_at`

func scanEnrollment(row interface{ Scan(...any) error }) (model.Enrollment, error) {
	var e model.Enrollment
	var id int64
	var enrolledAt sql.NullTime
	if err := row.Scan(&id, &e.Host, &e.Platform, &e.TokenHash, &e.Status, &e.CreatedAt, &enrolledAt); err != nil {
		return model.Enrollment{}, err
	}
	e.ID = strconv.FormatInt(id, 10)
	if enrolledAt.Valid {
		e.EnrolledAt = enrolledAt.Time
	}
	return e, nil
}

// CreateEnrollment persists a new pending enrollment for host.
func (s *Store) CreateEnrollment(ctx context.Context, host, platform, tokenHash string) (model.Enrollment, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO enrollments (host, platform, token_hash, status, created_at)
		VALUES ($1, $2, $3, 'pending', $4)
		RETURNING `+enrollmentColumns, host, platform, tokenHash, time.Now().UTC())
	e, err := scanEnrollment(row)
	if err != nil {
		return model.Enrollment{}, fmt.Errorf("pgstore: creating enrollment for %q: %w", host, err)
	}
	return e, nil
}

// ListEnrollments returns every enrollment, newest first.
func (s *Store) ListEnrollments(ctx context.Context) ([]model.Enrollment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+enrollmentColumns+` FROM enrollments ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing enrollments: %w", err)
	}
	defer rows.Close()

	out := []model.Enrollment{}
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, fmt.Errorf("pgstore: scanning enrollment: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// FindEnrollmentByHash looks up an enrollment by its token's hash.
func (s *Store) FindEnrollmentByHash(ctx context.Context, tokenHash string) (model.Enrollment, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+enrollmentColumns+` FROM enrollments WHERE token_hash = $1`, tokenHash)
	e, err := scanEnrollment(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Enrollment{}, false, nil
	}
	if err != nil {
		return model.Enrollment{}, false, fmt.Errorf("pgstore: looking up enrollment: %w", err)
	}
	return e, true, nil
}

// MarkEnrolled flips an enrollment to "enrolled" and stamps enrolled_at,
// the first time only -- COALESCE keeps a second call a harmless no-op
// rather than sliding EnrolledAt forward on every subsequent report.
func (s *Store) MarkEnrolled(ctx context.Context, id string) error {
	n, ok := actionRowID(id)
	if !ok {
		return store.ErrEnrollmentNotFound
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollments SET status = 'enrolled', enrolled_at = COALESCE(enrolled_at, $2)
		WHERE id = $1`, n, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("pgstore: marking enrollment %s enrolled: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrEnrollmentNotFound
	}
	return nil
}

// DeleteEnrollment revokes an enrollment by ID.
func (s *Store) DeleteEnrollment(ctx context.Context, id string) error {
	n, ok := actionRowID(id)
	if !ok {
		return store.ErrEnrollmentNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM enrollments WHERE id = $1`, n)
	if err != nil {
		return fmt.Errorf("pgstore: deleting enrollment %s: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return store.ErrEnrollmentNotFound
	}
	return nil
}

// compile-time check that Store satisfies store.Store.
var _ store.Store = (*Store)(nil)

// PutDocument creates or replaces the document keyed by (Kind, ID).
func (s *Store) PutDocument(ctx context.Context, doc model.Document) error {
	data := doc.Data
	if len(data) == 0 {
		data = json.RawMessage(`{}`)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO documents (kind, id, data, updated_at)
		VALUES ($1, $2, $3::jsonb, $4)
		ON CONFLICT (kind, id) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at`,
		doc.Kind, doc.ID, []byte(data), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("pgstore: putting document %s/%s: %w", doc.Kind, doc.ID, err)
	}
	return nil
}

// GetDocument returns the document keyed by (kind, id), if any.
func (s *Store) GetDocument(ctx context.Context, kind, id string) (model.Document, bool, error) {
	var d model.Document
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT kind, id, data, updated_at FROM documents WHERE kind = $1 AND id = $2`, kind, id).
		Scan(&d.Kind, &d.ID, &raw, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Document{}, false, nil
	}
	if err != nil {
		return model.Document{}, false, fmt.Errorf("pgstore: getting document %s/%s: %w", kind, id, err)
	}
	d.Data = json.RawMessage(raw)
	return d, true, nil
}

// ListDocuments returns every document of one kind, sorted by ID.
func (s *Store) ListDocuments(ctx context.Context, kind string) ([]model.Document, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, id, data, updated_at FROM documents WHERE kind = $1 ORDER BY id`, kind)
	if err != nil {
		return nil, fmt.Errorf("pgstore: listing documents of kind %q: %w", kind, err)
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var d model.Document
		var raw []byte
		if err := rows.Scan(&d.Kind, &d.ID, &raw, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("pgstore: scanning document: %w", err)
		}
		d.Data = json.RawMessage(raw)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDocument removes one document by (kind, id).
func (s *Store) DeleteDocument(ctx context.Context, kind, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM documents WHERE kind = $1 AND id = $2`, kind, id)
	if err != nil {
		return fmt.Errorf("pgstore: deleting document %s/%s: %w", kind, id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrDocumentNotFound
	}
	return nil
}
