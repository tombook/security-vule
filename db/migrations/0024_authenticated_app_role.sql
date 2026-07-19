-- 0024_authenticated_app_role.sql
-- 测试 / 非 superuser 角色:RLS 强制需要非 superuser 角色
-- 实际生产 app 仍是 superuser 跑,RLS 是为 worker / 报告服务准备

BEGIN;

DO $$ BEGIN
  CREATE ROLE authenticated_app NOLOGIN;
EXCEPTION WHEN duplicate_object THEN null; END $$;

GRANT USAGE ON SCHEMA core, detection, poc, usage, billing, governance, integration, meta TO authenticated_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core, detection, poc, usage, billing, governance, integration, meta TO authenticated_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA core, detection, poc, usage, billing, governance, integration, meta TO authenticated_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA core, detection, poc, usage, billing, governance, integration, meta GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authenticated_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA core, detection, poc, usage, billing, governance, integration, meta GRANT USAGE, SELECT ON SEQUENCES TO authenticated_app;

-- audit_logs 父表加 RLS policy(partitions 继承)
DO $$ BEGIN
  CREATE POLICY audit_logs_tenant ON governance.audit_logs
    FOR ALL TO PUBLIC
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
EXCEPTION WHEN duplicate_object THEN null; END $$;

COMMENT ON ROLE authenticated_app IS
  '非 superuser 应用角色;RLS 强制生效,生产 worker / 报告服务切换到此角色使用';

COMMIT;