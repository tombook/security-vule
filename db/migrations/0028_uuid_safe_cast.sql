-- 0028_uuid_safe_cast.sql
-- 修复 P0 测试发现的 RLS 政策 UUID cast bug:用 octet_length 守护 + ::text 比较

BEGIN;

DROP POLICY IF EXISTS customers_tenant ON core.customers;
CREATE POLICY customers_tenant ON core.customers
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS projects_tenant ON core.projects;
CREATE POLICY projects_tenant ON core.projects
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS findings_tenant ON detection.findings;
CREATE POLICY findings_tenant ON detection.findings
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS snapshots_tenant ON detection.snapshots;
CREATE POLICY snapshots_tenant ON detection.snapshots
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS scan_runs_tenant ON detection.scan_runs;
CREATE POLICY scan_runs_tenant ON detection.scan_runs
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS webhooks_tenant ON governance.webhooks;
CREATE POLICY webhooks_tenant ON governance.webhooks
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS ticket_integrations_tenant ON integration.ticket_integrations;
CREATE POLICY ticket_integrations_tenant ON integration.ticket_integrations
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS contacts_tenant ON core.contacts;
CREATE POLICY contacts_tenant ON core.contacts
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS sources_tenant ON core.sources;
CREATE POLICY sources_tenant ON core.sources
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS users_customer ON core.users;
CREATE POLICY users_customer ON core.users
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR customer_id IS NULL
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS customers_customer ON core.customers;
CREATE POLICY customers_customer ON core.customers
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) = ANY (ARRAY['ProviderOwner', 'ProviderAdmin', 'ProviderEngineer', 'ProviderViewer', 'ProviderAccountMgr', 'SystemBot'])
    )
  );

DROP POLICY IF EXISTS contacts_customer ON core.contacts;
CREATE POLICY contacts_customer ON core.contacts
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS sources_customer ON core.sources;
CREATE POLICY sources_customer ON core.sources
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS reports_customer ON core.reports;
CREATE POLICY reports_customer ON core.reports
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS findings_customer ON detection.findings;
CREATE POLICY findings_customer ON detection.findings
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS snapshots_customer ON detection.snapshots;
CREATE POLICY snapshots_customer ON detection.snapshots
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS scan_runs_customer ON detection.scan_runs;
CREATE POLICY scan_runs_customer ON detection.scan_runs
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS ticket_integrations_customer ON integration.ticket_integrations;
CREATE POLICY ticket_integrations_customer ON integration.ticket_integrations
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS projects_customer ON core.projects;
CREATE POLICY projects_customer ON core.projects
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) = ANY (ARRAY['ProviderOwner', 'ProviderEngineer', 'SystemBot'])
    )
  );

DROP POLICY IF EXISTS webhooks_customer ON governance.webhooks;
CREATE POLICY webhooks_customer ON governance.webhooks
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS notifications_customer ON governance.notifications;
CREATE POLICY notifications_customer ON governance.notifications
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

DROP POLICY IF EXISTS usage_events_tenant ON usage.usage_events;
CREATE POLICY usage_events_tenant ON usage.usage_events
  FOR ALL TO PUBLIC
  USING (
    current_setting('app.current_user_role', true) LIKE 'Provider%'
    AND octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS usage_events_customer ON usage.usage_events;
CREATE POLICY usage_events_customer ON usage.usage_events
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND (
      (octet_length(current_setting('app.current_customer', true)) = 36
        AND customer_id::text = current_setting('app.current_customer', true))
      OR current_setting('app.current_user_role', true) LIKE 'Provider%'
    )
  );

DROP POLICY IF EXISTS audit_logs_tenant ON governance.audit_logs;
CREATE POLICY audit_logs_tenant ON governance.audit_logs
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
    AND current_setting('app.current_user_role', true) LIKE 'Provider%'
  );

DROP POLICY IF EXISTS quota_policies_tenant ON usage.quota_policies;
CREATE POLICY quota_policies_tenant ON usage.quota_policies
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS billing_accounts_tenant ON billing.billing_accounts;
CREATE POLICY billing_accounts_tenant ON billing.billing_accounts
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS finding_state_history_tenant ON detection.finding_state_history;
CREATE POLICY finding_state_history_tenant ON detection.finding_state_history
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS finding_comments_tenant ON detection.finding_comments;
CREATE POLICY finding_comments_tenant ON detection.finding_comments
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS scan_run_engines_tenant ON detection.scan_run_engines;
CREATE POLICY scan_run_engines_tenant ON detection.scan_run_engines
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS quota_alerts_tenant ON usage.quota_alerts;
CREATE POLICY quota_alerts_tenant ON usage.quota_alerts
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

DROP POLICY IF EXISTS allocation_rules_tenant ON billing.allocation_rules;
CREATE POLICY allocation_rules_tenant ON billing.allocation_rules
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND billing_account_id IN (
      SELECT id FROM billing.billing_accounts
      WHERE octet_length(current_setting('app.current_tenant', true)) = 36
        AND tenant_id::text = current_setting('app.current_tenant', true)
    )
  );

DROP POLICY IF EXISTS invoices_tenant ON billing.invoices;
CREATE POLICY invoices_tenant ON billing.invoices
  FOR ALL TO PUBLIC
  USING (
    octet_length(current_setting('app.current_tenant', true)) = 36
    AND tenant_id::text = current_setting('app.current_tenant', true)
  );

COMMENT ON POLICY customers_tenant ON core.customers IS
  'P0 修复: octet_length=36 守护避免空 GUC cast 失败;tenant_id::text 比较';