-- Muster's Postgres schema. Applied automatically on every New() call via
-- CREATE ... IF NOT EXISTS -- there's no separate migration tool yet (see
-- README), so this file is the single source of truth for the schema.
--
-- Facts are stored as JSONB rather than unpacked into columns: different
-- categories (and different platforms, eventually) have different shapes,
-- and the whole point of internal/store.Store is that callers above it
-- treat a Fact's Data as an opaque, queryable document -- see model.Fact.

CREATE TABLE IF NOT EXISTS hosts (
    name        TEXT PRIMARY KEY,
    platform    TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_cooked TIMESTAMPTZ,
    -- Operator-assigned, never touched by the cook pipeline's UpsertHost:
    -- group_name drives the Kanban board's columns (a host lives in
    -- exactly one, like a Trello list); tags are freeform multi-valued
    -- labels shown on a card. Named group_name, not "group", so it never
    -- needs quoting as a reserved word in ordinary SQL.
    group_name  TEXT NOT NULL DEFAULT '',
    tags        TEXT[] NOT NULL DEFAULT '{}'
);

-- Covers a database created by an earlier version of this schema, before
-- group_name/tags existed -- see the "no real migration tool yet" note
-- in the README. Both are no-ops on a fresh database (the CREATE TABLE
-- above already has them).
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS group_name TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS facts (
    host      TEXT NOT NULL REFERENCES hosts (name) ON DELETE CASCADE,
    category  TEXT NOT NULL,
    data      JSONB NOT NULL,
    cooked_at TIMESTAMPTZ,
    PRIMARY KEY (host, category)
);

-- One row per changed field per cook run. Append-only: nothing ever
-- updates or deletes a row here, it's a history log.
CREATE TABLE IF NOT EXISTS changes (
    id         BIGSERIAL PRIMARY KEY,
    host       TEXT NOT NULL,
    category   TEXT NOT NULL,
    field      TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT,
    action     TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_facts_category ON facts (category);
CREATE INDEX IF NOT EXISTS idx_changes_host_time ON changes (host, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_hosts_group ON hosts (group_name);
