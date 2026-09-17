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
