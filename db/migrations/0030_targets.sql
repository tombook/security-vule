-- ── core.targets ─────────────────────────────────────────────────────
-- A target is a live URL (DVWA / Juice Shop / OWASP WebGoat / a
-- customer's staging instance / etc.) that the PoC verifier
-- actually exploits. One customer may have many targets; each
-- project can optionally pin a target so the PoC runner always
-- knows where to point its requests.
DO $$ BEGIN
  CREATE TYPE target_type_enum AS ENUM ('http', 'https', 'docker', 'ssh', 'mock');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE target_status_enum AS ENUM ('active', 'paused', 'broken', 'retired');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE target_auth_kind_enum AS ENUM ('none', 'basic', 'form', 'cookie', 'bearer', 'header');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE core.targets (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id       UUID NOT NULL,
  customer_id     UUID NOT NULL,
  project_id      UUID,
  name            TEXT NOT NULL,
  base_url        TEXT NOT NULL,
  target_type     target_type_enum NOT NULL DEFAULT 'http',
  auth_kind       target_auth_kind_enum NOT NULL DEFAULT 'none',
  auth_username   TEXT,
  auth_password_ciphertext BYTEA,
  auth_token_ciphertext    BYTEA,
  cookie_jar      JSONB NOT NULL DEFAULT '{}'::jsonb,
  allow_insecure  BOOLEAN NOT NULL DEFAULT FALSE,
  status          target_status_enum NOT NULL DEFAULT 'active',
  last_seen_at    TIMESTAMPTZ,
  last_health     TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_targets__tenant_name UNIQUE (tenant_id, customer_id, name)
);

CREATE INDEX idx_targets__tenant ON core.targets (tenant_id);
CREATE INDEX idx_targets__customer ON core.targets (customer_id);
CREATE INDEX idx_targets__project ON core.targets (project_id) WHERE project_id IS NOT NULL;

-- RLS: targets inherit tenant_id from the auth context.
ALTER TABLE core.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.targets FORCE ROW LEVEL SECURITY;

CREATE POLICY targets_tenant_isolation ON core.targets
  USING (
    current_setting('app.current_tenant', true) IS NULL
    OR tenant_id::text = current_setting('app.current_tenant', true)
  )
  WITH CHECK (
    current_setting('app.current_tenant', true) IS NULL
    OR tenant_id::text = current_setting('app.current_tenant', true)
  );

-- ── poc.poc_runs: extend with target_id + exploit outcome columns ─────
-- Existing schema (0014_validation.sql) already has:
--   poc_runs(id, finding_id, tenant_id, customer_id, poc_kind, payload,
--            status, requested_by, started_at, finished_at, duration_ms,
--            error_message, created_at, updated_at)
-- We add the bits the UI cares about for the "exploit_proven" badge:
--   target_id       which target the PoC was aimed at
--   http_status     final response status (e.g. 200 = success)
--   exploit_proven  whether the run successfully reproduced the vuln
--   evidence_url    link to request/response captured
--   stdout          captured verifier output (truncated)
ALTER TABLE poc.poc_runs
  ADD COLUMN IF NOT EXISTS target_id UUID,
  ADD COLUMN IF NOT EXISTS http_status INT,
  ADD COLUMN IF NOT EXISTS exploit_proven BOOLEAN,
  ADD COLUMN IF NOT EXISTS evidence_url TEXT,
  ADD COLUMN IF NOT EXISTS stdout TEXT;

CREATE INDEX IF NOT EXISTS idx_poc_runs__target ON poc.poc_runs (target_id) WHERE target_id IS NOT NULL;
