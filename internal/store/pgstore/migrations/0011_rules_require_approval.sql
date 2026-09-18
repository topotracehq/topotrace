-- 0011_rules_require_approval: a rule with an auto-remediation can ask
-- for a human to approve each queued action first -- see
-- model.Rule.RequireApproval and internal/alerts.

ALTER TABLE rules ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT false;
