-- db/migrations/0029_rls_gap_fixes.sql
-- 修复已知 RLS 缺口(R-01..R-05)
-- 来源:tests/integration/rls_coverage.test.ts 检测
BEGIN;

-- R-01: core.password_reset_tokens 加 tenant_isolation
-- 现有策略仅 SystemBot 可访问,需补 tenant 隔离(支持用户在忘记密码时验证 token 所属租户)
DROP POLICY IF EXISTS password_reset_tenant ON core.password_reset_tokens;
CREATE POLICY password_reset_tenant ON core.password_reset_tokens FOR ALL
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    OR current_setting('app.current_user_role', true) = 'SystemBot'
  );

-- R-02: billing.billing_accounts 加 customer_isolation
DROP POLICY IF EXISTS billing_accounts_customer ON billing.billing_accounts;
CREATE POLICY billing_accounts_customer ON billing.billing_accounts FOR ALL
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      customer_id = current_setting('app.current_customer', true)::uuid
      OR current_setting('app.current_user_role', true) IN (
        'ProviderOwner','ProviderAdmin','ProviderEngineer','ProviderViewer','ProviderBilling','SystemBot'
      )
    )
  );

-- R-03: billing.invoices 加 customer_isolation
DROP POLICY IF EXISTS invoices_customer ON billing.invoices;
CREATE POLICY invoices_customer ON billing.invoices FOR ALL
  USING (
    tenant_id = current_setting('app.current_tenant', true)::uuid
    AND (
      customer_id = current_setting('app.current_customer', true)::uuid
      OR current_setting('app.current_user_role', true) IN (
        'ProviderOwner','ProviderAdmin','ProviderBilling','SystemBot'
      )
    )
  );

-- R-04: billing.invoice_line_items 加 customer_isolation(通过 invoice_id 关联 invoices)
DROP POLICY IF EXISTS invoice_line_items_customer ON billing.invoice_line_items;
CREATE POLICY invoice_line_items_customer ON billing.invoice_line_items FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM billing.invoices inv
      WHERE inv.id = billing.invoice_line_items.invoice_id
        AND inv.tenant_id = current_setting('app.current_tenant', true)::uuid
        AND (
          inv.customer_id = current_setting('app.current_customer', true)::uuid
          OR current_setting('app.current_user_role', true) IN (
            'ProviderOwner','ProviderAdmin','ProviderBilling','SystemBot'
          )
        )
    )
  );

-- R-05: billing.allocation_rules 加 customer_isolation(通过 billing_account_id 关联 billing_accounts)
DROP POLICY IF EXISTS allocation_rules_customer ON billing.allocation_rules;
CREATE POLICY allocation_rules_customer ON billing.allocation_rules FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM billing.billing_accounts ba
      WHERE ba.id = billing.allocation_rules.billing_account_id
        AND ba.tenant_id = current_setting('app.current_tenant', true)::uuid
        AND (
          ba.customer_id = current_setting('app.current_customer', true)::uuid
          OR current_setting('app.current_user_role', true) IN (
            'ProviderOwner','ProviderAdmin','ProviderEngineer','ProviderBilling','SystemBot'
          )
        )
    )
  );

COMMIT;