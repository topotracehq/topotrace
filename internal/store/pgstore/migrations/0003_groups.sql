-- 0003_groups: board columns known to exist even with no host currently
-- in them -- see store.Store.CreateGroup's doc comment. SetHostGroup
-- inserts here too (ON CONFLICT DO NOTHING), so this table is always a
-- superset of the distinct group_name values actually on a host.

CREATE TABLE IF NOT EXISTS groups (
    name TEXT PRIMARY KEY
);
