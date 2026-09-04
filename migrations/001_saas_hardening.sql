-- SaaS hardening metadata added before public deployment.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_prefix varchar(12);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at timestamptz;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS runtime_json jsonb;

ALTER TABLE usage_events ALTER COLUMN scan_id DROP NOT NULL;
ALTER TABLE usage_events DROP CONSTRAINT IF EXISTS usage_events_scan_id_fkey;
ALTER TABLE usage_events
    ADD CONSTRAINT usage_events_scan_id_fkey
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_usage_events_org_type_created
    ON usage_events (org_id, event_type, created_at);

CREATE INDEX IF NOT EXISTS ix_scans_org_created
    ON scans (org_id, created_at DESC);
