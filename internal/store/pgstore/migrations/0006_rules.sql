-- 0006_rules: persisted, optionally group-scoped compliance rules --
-- see model.Rule and internal/evaluator. Deliberately a small fixed set
-- of Kind values, not an arbitrary expression language stored as text.

CREATE TABLE IF NOT EXISTS rules (
    id                  BIGSERIAL PRIMARY KEY,
    name                TEXT NOT NULL,
    group_name          TEXT NOT NULL DEFAULT '',
    kind                TEXT NOT NULL,
    threshold           INT NOT NULL DEFAULT 0,
    category            TEXT NOT NULL DEFAULT '',
    auto_remediate      TEXT NOT NULL DEFAULT '',
    auto_remediate_arg  TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
