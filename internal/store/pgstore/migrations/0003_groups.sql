--------------------------------------------------------------------------------
-- @file         0003_groups.sql
-- @brief        0003_groups: board columns known to exist even with no host currently in them -- see store.Store.CreateGroup's doc comment.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-17
-- @version      1.0.0
--
-- Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
-- Licensed under the MIT License -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0003_groups: board columns known to exist even with no host currently
-- in them -- see store.Store.CreateGroup's doc comment. SetHostGroup
-- inserts here too (ON CONFLICT DO NOTHING), so this table is always a
-- superset of the distinct group_name values actually on a host.

CREATE TABLE IF NOT EXISTS groups (
    name TEXT PRIMARY KEY
);
