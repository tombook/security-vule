-- 0025_fix_rls_role_check.sql
-- P0 测试发现的 RLS 安全漏洞修复:projects_tenant / *_tenant 类政策必须附加角色检查
-- 否则 Customer 角色能跨客户读同租户数据

BEGIN;

-- core.customers_tenant: 必须含角色检查(否则任何认证用户可看同租户所有客户)
DROP POLICY IF EXISTS customers_tenant ON core.customers;
CREATE POLICY customers_tenant ON core.customers
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- core.projects_tenant
DROP POLICY IF EXISTS projects_tenant ON core.projects;
CREATE POLICY projects_tenant ON core.projects
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- detection.findings_tenant
DROP POLICY IF EXISTS findings_tenant ON detection.findings;
CREATE POLICY findings_tenant ON detection.findings
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- detection.snapshots_tenant
DROP POLICY IF EXISTS snapshots_tenant ON detection.snapshots;
CREATE POLICY snapshots_tenant ON detection.snapshots
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- detection.scan_runs_tenant
DROP POLICY IF EXISTS scan_runs_tenant ON detection.scan_runs;
CREATE POLICY scan_runs_tenant ON detection.scan_runs
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- governance.webhooks_tenant
DROP POLICY IF EXISTS webhooks_tenant ON governance.webhooks;
CREATE POLICY webhooks_tenant ON governance.webhooks
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- integration.ticket_integrations_tenant
DROP POLICY IF EXISTS ticket_integrations_tenant ON integration.ticket_integrations;
CREATE POLICY ticket_integrations_tenant ON integration.ticket_integrations
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- core.contacts_tenant
DROP POLICY IF EXISTS contacts_tenant ON core.contacts;
CREATE POLICY contacts_tenant ON core.contacts
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- core.sources_tenant
DROP POLICY IF EXISTS sources_tenant ON core.sources;
CREATE POLICY sources_tenant ON core.sources
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

-- core.users_customer (混合 customer_id 隔离也加角色限制)
DROP POLICY IF EXISTS users_customer ON core.users;
CREATE POLICY users_customer ON core.users
  FOR ALL TO PUBLIC
  USING (
    NULLIF(current_setting('app.current_tenant', true), '') IS NOT NULL
    AND tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR (customer_id IS NULL AND current_setting('app.current_user_role', true) LIKE 'Provider%')
      OR (current_setting('app.current_user_role', true) LIKE 'Provider%')
    )
  );

-- 注释
COMMENT ON POLICY customers_tenant ON core.customers IS
  'P0 修复: 显式要求 Provider 角色,避免 Customer 角色跨客户读';

COMMIT;