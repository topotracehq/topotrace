--------------------------------------------------------------------------------
-- @file         0011_rules_require_approval.sql
-- @brief        0011_rules_require_approval: a rule with an auto-remediation can ask for a human to approve each queued action first -- see model.Rule.RequireApproval and internal/alerts.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-18
-- @version      1.0.0
--
-- Copyright (c) 2026 TopoTrace LLC. All rights reserved.
-- Licensed under the MIT License -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0011_rules_require_approval: a rule with an auto-remediation can ask
-- for a human to approve each queued action first -- see
-- model.Rule.RequireApproval and internal/alerts.

ALTER TABLE rules ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT false;
