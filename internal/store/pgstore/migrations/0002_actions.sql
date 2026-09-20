--------------------------------------------------------------------------------
-- @file         0002_actions.sql
-- @brief        0002_actions: remediation action queue.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-17
-- @version      1.0.0
--
-- Copyright (c) 2026 TopoTrace LLC. All rights reserved.
-- Licensed under the MIT License -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0002_actions: remediation action queue. See internal/remediate for the
-- fixed allow-list a Verb is ever drawn from -- this table just records
-- what was queued and what an agent said it did, it doesn't enforce the
-- allow-list itself (internal/api does, before a row is ever inserted).

CREATE TABLE IF NOT EXISTS actions (
    id           BIGSERIAL PRIMARY KEY,
    host         TEXT NOT NULL REFERENCES hosts (name) ON DELETE CASCADE,
    verb         TEXT NOT NULL,
    arg          TEXT NOT NULL DEFAULT '',
    queued_at    TIMESTAMPTZ NOT NULL,
    delivered    BOOLEAN NOT NULL DEFAULT FALSE,
    delivered_at TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    reported_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_actions_host_queued ON actions (host, queued_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_pending ON actions (host, delivered) WHERE delivered = FALSE;
