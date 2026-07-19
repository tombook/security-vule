-- 0020_rls_policies_and_reports_type.sql
-- Phase 0 修复:补 30 张表 RLS policy + core.reports 列类型改为 enum

BEGIN;

-- ============================================================
-- Part 1: 修复 core.reports 列类型(裸 TEXT → enum)
-- ============================================================

ALTER TABLE core.reports
  ALTER COLUMN report_type DROP DEFAULT,
  ALTER COLUMN report_type TYPE report_type_enum
    USING CASE report_type
      WHEN 'weekly' THEN 'weekly'::report_type_enum
      WHEN 'monthly' THEN 'monthly'::report_type_enum
      WHEN 'single_finding' THEN 'single_finding'::report_type_enum
      WHEN 'compliance' THEN 'compliance'::report_type_enum
      WHEN 'asset_snapshot' THEN 'asset_snapshot'::report_type_enum
      ELSE 'monthly'::report_type_enum
    END,
  ALTER COLUMN report_type SET DEFAULT 'monthly'::report_type_enum;

ALTER TABLE core.reports
  ALTER COLUMN format DROP DEFAULT,
  ALTER COLUMN format TYPE report_format_enum
    USING CASE format
      WHEN 'html' THEN 'html'::report_format_enum
      WHEN 'pdf' THEN 'pdf'::report_format_enum
      WHEN 'markdown' THEN 'markdown'::report_format_enum
      WHEN 'json' THEN 'json'::report_format_enum
      ELSE 'pdf'::report_format_enum
    END,
  ALTER COLUMN format SET DEFAULT 'pdf'::report_format_enum;

ALTER TABLE core.reports
  ALTER COLUMN status DROP DEFAULT,
  ALTER COLUMN status TYPE report_status_enum
    USING CASE status
      WHEN 'pending' THEN 'pending'::report_status_enum
      WHEN 'generating' THEN 'generating'::report_status_enum
      WHEN 'ready' THEN 'ready'::report_status_enum
      WHEN 'failed' THEN 'failed'::report_status_enum
      ELSE 'pending'::report_status_enum
    END,
  ALTER COLUMN status SET DEFAULT 'pending'::report_status_enum;

COMMENT ON COLUMN core.reports.report_type IS 'weekly | monthly | single_finding | compliance | asset_snapshot';
COMMENT ON COLUMN core.reports.format IS 'html | pdf | markdown | json';
COMMENT ON COLUMN core.reports.status IS 'pending | generating | ready | failed';

-- ============================================================
-- Part 2: 补 RLS policies(30 张表)
-- 模式:tenant_id 隔离 + customer_id 二级隔离
-- ============================================================

-- ----- core.* -----

-- core.sessions (会话记录)
CREATE POLICY sessions_tenant ON core.sessions
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- core.invites (邀请)
CREATE POLICY invites_tenant ON core.invites
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- core.contacts (客户联系人)
CREATE POLICY contacts_tenant ON core.contacts
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY contacts_customer ON core.contacts
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

-- core.api_keys (API 密钥)
CREATE POLICY api_keys_tenant ON core.api_keys
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- core.source_sync_history (代码源同步历史)
CREATE POLICY source_sync_tenant ON core.source_sync_history
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- core.sources (代码源)
CREATE POLICY sources_tenant ON core.sources
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY sources_customer ON core.sources
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

-- core.reports (报告)
CREATE POLICY reports_tenant ON core.reports
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY reports_customer ON core.reports
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

-- ----- detection.* -----

-- detection.engines (引擎元数据,可能为 NULL tenant_id 表示平台内置)
CREATE POLICY engines_tenant ON detection.engines
  FOR ALL TO PUBLIC
  USING (tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant', true)::uuid
    OR current_setting('app.current_user_role', true) = 'SystemBot');

-- detection.rules (indirect via engine_id)
CREATE POLICY rules_tenant ON detection.rules
  FOR ALL TO PUBLIC
  USING (engine_id IN (
    SELECT id FROM detection.engines
    WHERE tenant_id IS NULL
       OR tenant_id = current_setting('app.current_tenant', true)::uuid
       OR current_setting('app.current_user_role', true) = 'SystemBot'
  ));

-- detection.policy_configs
CREATE POLICY policy_configs_tenant ON detection.policy_configs
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY policy_versions_tenant ON detection.policy_versions
  FOR ALL TO PUBLIC
  USING (policy_id IN (
    SELECT id FROM detection.policy_configs
    WHERE tenant_id = current_setting('app.current_tenant', true)::uuid
  ));

-- detection.snapshots
CREATE POLICY snapshots_tenant ON detection.snapshots
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY snapshots_customer ON detection.snapshots
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

-- detection.scan_runs
CREATE POLICY scan_runs_tenant ON detection.scan_runs
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY scan_runs_customer ON detection.scan_runs
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

-- detection.scan_run_engines
CREATE POLICY scan_run_engines_tenant ON detection.scan_run_engines
  FOR ALL TO PUBLIC
  USING (scan_run_id IN (
    SELECT id FROM detection.scan_runs
    WHERE tenant_id = current_setting('app.current_tenant', true)::uuid
  ));

-- detection.findings
CREATE POLICY findings_tenant ON detection.findings
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY findings_customer ON detection.findings
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

-- detection.finding_state_history
CREATE POLICY finding_state_history_tenant ON detection.finding_state_history
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- detection.finding_comments
CREATE POLICY finding_comments_tenant ON detection.finding_comments
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- detection.pr_scan_checks
CREATE POLICY pr_scan_checks_tenant ON detection.pr_scan_checks
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ----- poc.* -----

-- poc.poc_runs
CREATE POLICY poc_runs_tenant ON poc.poc_runs
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY poc_runs_customer ON poc.poc_runs
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

CREATE POLICY poc_sandboxes_tenant ON poc.poc_sandboxes
  FOR ALL TO PUBLIC
  USING (poc_run_id IN (
    SELECT id FROM poc.poc_runs
    WHERE tenant_id = current_setting('app.current_tenant', true)::uuid
  ));

-- poc.poc_library
CREATE POLICY poc_library_tenant ON poc.poc_library
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- poc.poc_chat_messages
CREATE POLICY poc_chat_messages_tenant ON poc.poc_chat_messages
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- poc.exploit_chains
CREATE POLICY exploit_chains_tenant ON poc.exploit_chains
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ----- usage.* -----

-- usage.usage_events
CREATE POLICY usage_events_tenant ON usage.usage_events
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY usage_events_customer ON usage.usage_events
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR customer_id IS NULL
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

-- usage.quota_policies
CREATE POLICY quota_policies_tenant ON usage.quota_policies
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- usage.quota_alerts
CREATE POLICY quota_alerts_tenant ON usage.quota_alerts
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ----- billing.* -----

-- billing.billing_accounts
CREATE POLICY billing_accounts_tenant ON billing.billing_accounts
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- billing.allocation_rules
CREATE POLICY allocation_rules_tenant ON billing.allocation_rules
  FOR ALL TO PUBLIC
  USING (billing_account_id IN (
    SELECT id FROM billing.billing_accounts
    WHERE tenant_id = current_setting('app.current_tenant', true)::uuid
  ));

-- billing.invoices
CREATE POLICY invoices_tenant ON billing.invoices
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- billing.invoice_line_items
CREATE POLICY invoice_line_items_tenant ON billing.invoice_line_items
  FOR ALL TO PUBLIC
  USING (invoice_id IN (
    SELECT id FROM billing.invoices
    WHERE tenant_id = current_setting('app.current_tenant', true)::uuid
  ));

-- ----- governance.* -----

-- governance.webhooks
CREATE POLICY webhooks_tenant ON governance.webhooks
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- governance.webhook_deliveries
CREATE POLICY webhook_deliveries_tenant ON governance.webhook_deliveries
  FOR ALL TO PUBLIC
  USING (webhook_id IN (
    SELECT id FROM governance.webhooks
    WHERE tenant_id = current_setting('app.current_tenant', true)::uuid
  ));

-- governance.tenant_data_exports
CREATE POLICY tenant_data_exports_tenant ON governance.tenant_data_exports
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- governance.notifications
CREATE POLICY notifications_tenant ON governance.notifications
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ----- integration.* -----

-- integration.ticket_integrations
CREATE POLICY ticket_integrations_tenant ON integration.ticket_integrations
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ticket_integrations_customer ON integration.ticket_integrations
  FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (customer_id = NULLIF(current_setting('app.current_customer', true), '')::uuid
         OR current_setting('app.current_user_role', true) LIKE 'Provider%'));

COMMIT;