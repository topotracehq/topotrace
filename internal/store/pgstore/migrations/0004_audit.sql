--------------------------------------------------------------------------------
-- @file         0004_audit.sql
-- @brief        0004_audit: an append-only log of authenticated writes and remediation events, for after-the-fact accountability.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-17
-- @version      1.0.0
--
-- Copyright (c) 2026 TopoTrace LLC. All rights reserved.
-- Licensed under the MIT License -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0004_audit: an append-only log of authenticated writes and
-- remediation events, for after-the-fact accountability. See
-- model.AuditEntry -- actor is an API key's name, "master" for the
-- bootstrap -auth-token, or "system" for the background evaluator.

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_target_time ON audit_log (target, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log (created_at DESC);
