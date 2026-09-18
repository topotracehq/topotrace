--------------------------------------------------------------------------------
-- @file         0012_api_keys_group.sql
-- @brief        0012_api_keys_group: an API key can be scoped to one board group -- see model.APIKey.Group and internal/api's scope enforcement.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-18
-- @version      1.0.0
--
-- Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
-- Licensed under the MIT License -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0012_api_keys_group: an API key can be scoped to one board group --
-- see model.APIKey.Group and internal/api's scope enforcement.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS group_name TEXT NOT NULL DEFAULT '';
