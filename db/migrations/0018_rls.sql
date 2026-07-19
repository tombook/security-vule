BEGIN;

ALTER TABLE core.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.source_sync_history ENABLE ROW LEVEL SECURITY;

ALTER TABLE detection.engines ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.engine_health_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.policy_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.scan_run_engines ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.finding_state_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.finding_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.pr_scan_checks ENABLE ROW LEVEL SECURITY;

ALTER TABLE poc.poc_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc.poc_sandboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc.poc_library ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc.exploit_chains ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc.poc_chat_messages ENABLE ROW LEVEL SECURITY;

ALTER TABLE usage.usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.quota_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage.quota_alerts ENABLE ROW LEVEL SECURITY;

ALTER TABLE billing.billing_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing.plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing.allocation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing.invoice_line_items ENABLE ROW LEVEL SECURITY;

ALTER TABLE governance.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.tenant_data_exports ENABLE ROW LEVEL SECURITY;

ALTER TABLE integration.ticket_integrations ENABLE ROW LEVEL SECURITY;

ALTER TABLE meta.scheduled_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_tenant ON core.users FOR ALL
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY users_customer ON core.users FOR ALL
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      customer_id = current_setting('app.current_customer', true)::uuid
      OR customer_id IS NULL
      OR current_setting('app.current_user_role', true) IN (
        'ProviderOwner','ProviderAdmin','ProviderEngineer','ProviderViewer','SystemBot'
      )
    )
  );

CREATE POLICY customers_tenant ON core.customers FOR ALL
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY customers_customer ON core.customers FOR ALL
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      id = current_setting('app.current_customer', true)::uuid
      OR current_setting('app.current_user_role', true) IN (
        'ProviderOwner','ProviderAdmin','ProviderEngineer','ProviderAccountMgr','ProviderViewer','SystemBot'
      )
    )
  );

CREATE POLICY projects_tenant ON core.projects FOR ALL
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY projects_customer ON core.projects FOR ALL
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      customer_id = current_setting('app.current_customer', true)::uuid
      OR current_setting('app.current_user_role', true) IN (
        'ProviderOwner','ProviderEngineer','SystemBot'
      )
    )
  );

CREATE POLICY password_reset_system_only ON core.password_reset_tokens FOR ALL
  USING (current_setting('app.current_user_role', true) = 'SystemBot');

CREATE POLICY scheduled_jobs_system_only ON meta.scheduled_jobs FOR ALL
  USING (current_setting('app.current_user_role', true) = 'SystemBot');

CREATE POLICY engine_health_isolation ON detection.engine_health_checks FOR ALL
  USING (
    tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant', true)::uuid
    OR current_setting('app.current_user_role', true) = 'SystemBot'
  );

CREATE POLICY plans_provider_owner ON billing.plans FOR ALL
  USING (current_setting('app.current_user_role', true) IN ('ProviderOwner','SystemBot'));
CREATE POLICY plans_public_visible ON billing.plans FOR SELECT
  USING (
    is_public AND status = 'active'
    AND current_setting('app.current_user_role', true) IN (
      'CustomerAdmin','CustomerDeveloper','ProviderOwner','ProviderAccountMgr','SystemBot'
    )
  );

COMMIT;
