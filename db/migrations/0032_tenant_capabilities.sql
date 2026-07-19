-- 0032_tenant_capabilities.sql
--
-- Per-tenant enable / disable of the 8 white-box detection
-- capabilities (sqli / xss / cmd / ssrf / traversal / secret /
-- md5 / eval). Defaults to 'enabled = true' for every capability
-- so the operator has to opt-out, not opt-in.
--
-- The capability id is a free-form string so we can add new
-- patterns to apps/api/src/routes/scans.ts (runMockScan) and
-- /detection/capabilities without a database migration.
CREATE TABLE IF NOT EXISTS detection.tenant_capabilities (
    tenant_id     UUID         NOT NULL,
    capability_id TEXT         NOT NULL,
    enabled       BOOLEAN      NOT NULL DEFAULT true,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_by    UUID,
    PRIMARY KEY (tenant_id, capability_id),
    FOREIGN KEY (tenant_id) REFERENCES core.tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_capabilities__tenant
    ON detection.tenant_capabilities(tenant_id);

-- Seed: ensure every existing tenant has a row for every known
-- capability. Using ON CONFLICT DO NOTHING means re-runs are safe.
-- We list the 8 known ids inline here — keep in sync with
-- apps/api/src/routes/detection.ts /capabilities.
INSERT INTO detection.tenant_capabilities (tenant_id, capability_id, enabled)
SELECT t.id, c.capability_id, true
  FROM core.tenants t
  CROSS JOIN (VALUES
    ('sqli'), ('xss'), ('cmd'), ('ssrf'),
    ('traversal'), ('secret'), ('md5'), ('eval')
  ) AS c(capability_id)
 ON CONFLICT (tenant_id, capability_id) DO NOTHING;

-- RLS: matches the pattern used by every other detection table —
-- scoped to the calling tenant via the RLS session variable set
-- by the API's tenant middleware.
ALTER TABLE detection.tenant_capabilities ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_capabilities_tenant_isolation
    ON detection.tenant_capabilities
    FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
