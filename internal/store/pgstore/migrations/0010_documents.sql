-- 0010_documents: generic (kind, id) -> JSON records for secondary
-- per-object state -- see model.Document for what belongs here (score
-- history, config baselines, remediation approvals, demo bookmarks,
-- agent health) and what deliberately doesn't (anything queried across
-- hosts at scale keeps its own table).

CREATE TABLE IF NOT EXISTS documents (
    kind        TEXT NOT NULL,
    id          TEXT NOT NULL,
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, id)
);
