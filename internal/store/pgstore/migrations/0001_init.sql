--------------------------------------------------------------------------------
-- @file         0001_init.sql
-- @brief        0001_init: hosts, facts, changes -- the original schema, from before muster had a migration runner at all.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-14
-- @version      1.0.0
--
-- Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
-- Licensed under the MIT License -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0001_init: hosts, facts, changes -- the original schema, from before
-- muster had a migration runner at all. group_name/tags are included
-- directly here (no separate ALTER TABLE compat step needed -- a
-- database created by a pre-migrations muster already has them, and
-- this migration never runs against it again once schema_migrations
-- records 0001 as applied by the one-time bootstrap in pgstore.New).

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
