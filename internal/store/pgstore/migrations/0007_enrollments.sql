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
