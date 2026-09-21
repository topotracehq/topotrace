--------------------------------------------------------------------------------
-- @file         0007_enrollments.sql
-- @brief        Part of the Muster migrations module.
-- @project      Muster
--
-- @author       Michael McGinnis
-- @date         2026-09-17
-- @version      1.0.0
--
-- Copyright (c) 2026 TopoTrace LLC. All rights reserved.
-- Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
--------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS enrollments (
    id          BIGSERIAL PRIMARY KEY,
    host        TEXT NOT NULL,
    platform    TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    enrolled_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_enrollments_host ON enrollments (host);
