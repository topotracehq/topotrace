--------------------------------------------------------------------------------
-- @file         0005_api_keys.sql
-- @brief        0005_api_keys: named, role-scoped credentials on top of the original single shared -auth-token (which keeps working unchanged as a permanent "admin" master credential -- see internal/api).
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-17
-- @version      1.0.0
--
-- Copyright (c) 2026 TopoTrace LLC. All rights reserved.
-- Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

-- 0005_api_keys: named, role-scoped credentials on top of the original
-- single shared -auth-token (which keeps working unchanged as a
-- permanent "admin" master credential -- see internal/api). Only the
-- SHA-256 hash of a key's raw token is ever stored; the raw value is
-- shown once, at creation time, and never persisted anywhere.

CREATE TABLE IF NOT EXISTS api_keys (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
