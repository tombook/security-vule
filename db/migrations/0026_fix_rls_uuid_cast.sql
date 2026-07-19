-- 0026_fix_rls_uuid_cast.sql
-- P0 测试发现的 RLS 政策 bug:`current_setting(..., '')::uuid` 中 `''::uuid` 先于 NULLIF 失败
-- 修复:用 CASE WHEN 显式短路

BEGIN;

DROP POLICY IF EXISTS customers_customer ON core.customers;
CREATE POLICY customers_customer ON core.customers
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) = ANY (ARRAY['ProviderOwner', 'ProviderAdmin', 'ProviderEngineer', 'ProviderViewer', 'ProviderAccountMgr', 'SystemBot'])
    )
  );

-- core.contacts_customer
DROP POLICY IF EXISTS contacts_customer ON core.contacts;
CREATE POLICY contacts_customer ON core.contacts
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- core.sources_customer
DROP POLICY IF EXISTS sources_customer ON core.sources;
CREATE POLICY sources_customer ON core.sources
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- core.reports_customer
DROP POLICY IF EXISTS reports_customer ON core.reports;
CREATE POLICY reports_customer ON core.reports
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- detection.findings_customer
DROP POLICY IF EXISTS findings_customer ON detection.findings;
CREATE POLICY findings_customer ON detection.findings
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- detection.snapshots_customer
DROP POLICY IF EXISTS snapshots_customer ON detection.snapshots;
CREATE POLICY snapshots_customer ON detection.snapshots
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- detection.scan_runs_customer
DROP POLICY IF EXISTS scan_runs_customer ON detection.scan_runs;
CREATE POLICY scan_runs_customer ON detection.scan_runs
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- core.users_customer
DROP POLICY IF EXISTS users_customer ON core.users;
CREATE POLICY users_customer ON core.users
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR customer_id IS NULL
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- integration.ticket_integrations_customer
DROP POLICY IF EXISTS ticket_integrations_customer ON integration.ticket_integrations;
CREATE POLICY ticket_integrations_customer ON integration.ticket_integrations
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

-- core.projects_customer
DROP POLICY IF EXISTS projects_customer ON core.projects;
CREATE POLICY projects_customer ON core.projects
  FOR ALL TO PUBLIC
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      (NULLIF(current_setting('app.current_customer', true), '') IS NOT NULL
        AND customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid)
      OR current_setting('app.current_user_role', true) = ANY (ARRAY['ProviderOwner', 'ProviderEngineer', 'SystemBot'])
    )
  );

COMMENT ON POLICY customers_customer ON core.customers IS
  'P0 修复: `NULLIF IS NOT NULL` 短路避免 `''''::uuid` 错误';

COMMIT;