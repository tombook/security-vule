-- 0022_tenant_applications_and_oauth_states.sql
-- Loop 1 接入闭环需要的 2 张新表
-- 1. meta.tenant_applications 申请记录(平台运营可查)
-- 2. core.oauth_states OAuth CSRF 状态(防 CSRF)

BEGIN;

DO $$ BEGIN
  CREATE TYPE application_status_enum AS ENUM ('pending', 'approved', 'rejected', 'withdrawn');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE oauth_provider_enum AS ENUM ('github', 'gitlab', 'google', 'azure', 'bitbucket');
EXCEPTION WHEN duplicate_object THEN null; END $$;

CREATE TABLE IF NOT EXISTS meta.tenant_applications (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  company_name        TEXT NOT NULL,
  contact_name        TEXT NOT NULL,
  contact_email       CITEXT NOT NULL,
  contact_phone       TEXT,
  service_scale       TEXT,
  customer_volume     TEXT,
  status              application_status_enum NOT NULL DEFAULT 'pending',
  rejection_reason    TEXT,
  reviewed_by         UUID,
  reviewed_at         TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_applications__status_time
  ON meta.tenant_applications(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_applications__email
  ON meta.tenant_applications(contact_email);

COMMENT ON TABLE meta.tenant_applications IS
  '服务商入驻申请;平台运营审核通过后调用 POST /admin/tenants/:id/approve 创建 core.tenants';

CREATE TABLE IF NOT EXISTS core.oauth_states (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
  state           TEXT NOT NULL UNIQUE,
  provider        oauth_provider_enum NOT NULL,
  tenant_id       UUID NOT NULL REFERENCES core.tenants(id),
  customer_id     UUID NOT NULL REFERENCES core.customers(id),
  project_id      UUID NOT NULL REFERENCES core.projects(id),
  redirect_after  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 min'
);

CREATE INDEX IF NOT EXISTS idx_oauth_states__expires
  ON core.oauth_states(expires_at);

COMMENT ON TABLE core.oauth_states IS
  'OAuth CSRF 状态;10 分钟过期,callback 时验证 + 立即删除';

ALTER TABLE core.oauth_states ENABLE ROW LEVEL SECURITY;

CREATE POLICY oauth_states_tenant ON core.oauth_states
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMIT;