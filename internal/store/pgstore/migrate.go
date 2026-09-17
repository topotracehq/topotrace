package pgstore

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

// migrationsFS embeds every numbered migration file (0001_init.sql,
// 0002_actions.sql, ...) into the muster binary, so a deployment is just
// "run the binary against an empty database" -- no separate migration
// tool or file layout to ship alongside it.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationsTable tracks which migration files have already been
// applied to this database, by filename (e.g. "0001_init.sql"). It's
// created before anything else, so New() can always tell a brand-new
// database (nothing applied yet) from one that predates the migration
// runner but already has hosts/facts/changes/actions/groups from the
// old single schema.sql -- see the backfill note in applyMigrations.
const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// applyMigrations brings db's schema up to date by running every
// migrations/*.sql file that isn't yet recorded in schema_migrations, in
// filename order, each inside its own transaction. Every statement in
// every migration is CREATE ... IF NOT EXISTS, so even the first run
// against a database built by the pre-migrations schema.sql (before
// this backlog item) is safe -- the CREATEs are no-ops there and the
// migration is simply recorded as applied without changing anything.
func applyMigrations(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names) // "0001_init.sql" < "0002_actions.sql" < ... by construction

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return fmt.Errorf("reading applied migrations: %w", err)
	}

	for _, name := range names {
		if applied[name] {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("reading embedded migration %s: %w", name, err)
		}
		if err := applyOne(ctx, db, name, string(sqlBytes)); err != nil {
			return fmt.Errorf("applying migration %s: %w", name, err)
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

// applyOne runs one migration file's SQL and records it as applied in a
// single transaction, so a crash or connection loss mid-migration never
// leaves the database schema changed but not recorded (which would make
// the next startup skip a migration it actually needs).
func applyOne(ctx context.Context, db *sql.DB, name, sqlText string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once committed

	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
		return err
	}
	return tx.Commit()
}
