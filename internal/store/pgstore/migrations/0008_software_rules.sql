--------------------------------------------------------------------------------
-- @file         0008_software_rules.sql
-- @brief        0008_software_rules: persisted, optionally group-scoped software allow/deny rules -- see model.SoftwareRule and internal/allowlist.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-17
-- @version      1.0.0
--
-- Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
-- Licensed under the MIT License -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0008_software_rules: persisted, optionally group-scoped software
-- allow/deny rules -- see model.SoftwareRule and internal/allowlist.

CREATE TABLE IF NOT EXISTS software_rules (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    group_name  TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,
    match       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
