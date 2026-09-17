-- 0009_discovered_assets: network/asset discovery sightings (cmd/discover)
-- -- see model.DiscoveredAsset. Address is unique so a repeat scan
-- upserts the existing row (refreshing open_ports/banners/known/
-- last_seen_at) instead of piling up duplicates for the same address.

CREATE TABLE IF NOT EXISTS discovered_assets (
    id            BIGSERIAL PRIMARY KEY,
    address       TEXT NOT NULL UNIQUE,
    open_ports    INTEGER[] NOT NULL DEFAULT '{}',
    banners       JSONB NOT NULL DEFAULT '{}'::jsonb,
    scanned_by    TEXT NOT NULL DEFAULT '',
    scanned_cidr  TEXT NOT NULL DEFAULT '',
    known         BOOLEAN NOT NULL DEFAULT false,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
