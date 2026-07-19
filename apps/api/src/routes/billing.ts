import { Hono } from 'hono';
import { pool } from '../db/client';
import { requireRole, PROVIDER_ADMIN_ROLES, PROVIDER_BILLING_ROLES } from '../middleware/rbac';

export const billingRoutes = new Hono()
  .get('/plans', async (c) => {
    requireRole(c, [...PROVIDER_ADMIN_ROLES, 'ProviderBilling']);
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, code, display_name, description, monthly_token_quota,
              monthly_customer_limit, monthly_project_limit, overage_rate_usd_per_1k,
              price_usd, currency, billing_period, features, status, effective_from, effective_to,
              is_public, display_order, created_at
       FROM billing.plans
       WHERE status = 'active' AND (is_public OR effective_to IS NULL)
       ORDER BY display_order`,
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, code: r.code, displayName: r.display_name, description: r.description,
        monthlyTokenQuota: r.monthly_token_quota, monthlyCustomerLimit: r.monthly_customer_limit,
        monthlyProjectLimit: r.monthly_project_limit, overageRateUsdPer1k: r.overage_rate_usd_per_1k,
        priceUsd: r.price_usd, currency: r.currency, billingPeriod: r.billing_period,
        features: r.features, status: r.status, effectiveFrom: r.effective_from, effectiveTo: r.effective_to,
        isPublic: r.is_public, displayOrder: r.display_order, createdAt: r.created_at,
      })),
    });
  })
  .get('/quota', async (c) => {
    const pg = c.get('pg');
    const { rows: usageRows } = await pg.query(
      `SELECT capability, sum(total_tokens)::bigint as tokens
       FROM usage.usage_events
       WHERE tenant_id = $1 AND occurred_at >= date_trunc('month', NOW())
       GROUP BY capability`,
      [c.get('user').tenantId],
    );
    const { rows: planRows } = await pg.query(
      `SELECT ba.plan, ba.monthly_token_quota, ba.status, ba.balance_usd
       FROM billing.billing_accounts ba
       JOIN core.customers c ON c.id = ba.customer_id
       WHERE ba.tenant_id = $1 AND ba.status = 'active'
       LIMIT 1`,
      [c.get('user').tenantId],
    );
    const { rows: alertRows } = await pg.query(
      `SELECT capability, alert_level, used_tokens, limit_tokens
       FROM usage.quota_alerts
       WHERE tenant_id = $1 AND period_start = date_trunc('month', NOW())
       ORDER BY occurred_at DESC
       LIMIT 5`,
      [c.get('user').tenantId],
    );
    const used = usageRows.reduce((s: number, r: any) => s + Number(r.tokens), 0);
    return c.json({
      currentPlan: planRows[0] ? {
        plan: planRows[0].plan, monthlyTokenQuota: Number(planRows[0].monthly_token_quota),
        status: planRows[0].status, balanceUsd: Number(planRows[0].balance_usd),
      } : null,
      usageThisMonth: {
        total: used, byCapability: Object.fromEntries(usageRows.map((r: any) => [r.capability, Number(r.tokens)])),
      },
      recentAlerts: alertRows.map((r: any) => ({
        capability: r.capability, level: r.alert_level,
        used: Number(r.used_tokens), limit: Number(r.limit_tokens),
      })),
    });
  })
  .get('/invoices', async (c) => {
    requireRole(c, [...PROVIDER_ADMIN_ROLES, 'ProviderBilling']);
    const pg = c.get('pg');
    const customerId = c.req.query('customer_id');
    const params: unknown[] = [c.get('user').tenantId];
    let where = 'i.tenant_id = $1';
    if (customerId) {
      params.push(customerId);
      where += ` AND i.customer_id = $${params.length}::uuid`;
    }
    const { rows } = await pg.query(
      `SELECT i.id, i.invoice_number, i.customer_id, i.billing_account_id,
              i.period_start, i.period_end, i.subtotal_usd, i.tax_usd, i.total_usd,
              i.status, i.issued_at, i.due_at, i.paid_at, i.created_at,
              c.name as customer_name,
              (SELECT count(*) FROM billing.invoice_line_items WHERE invoice_id = i.id)::int as line_item_count
       FROM billing.invoices i
       LEFT JOIN core.customers c ON c.id = i.customer_id
       WHERE ${where}
       ORDER BY i.created_at DESC
       LIMIT 100`,
      params,
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, invoiceNumber: r.invoice_number, customerId: r.customer_id, customerName: r.customer_name,
        billingAccountId: r.billing_account_id, periodStart: r.period_start, periodEnd: r.period_end,
        subtotalUsd: Number(r.subtotal_usd), taxUsd: Number(r.tax_usd), totalUsd: Number(r.total_usd),
        status: r.status, issuedAt: r.issued_at, dueAt: r.due_at, paidAt: r.paid_at,
        lineItemCount: r.line_item_count, createdAt: r.created_at,
      })),
    });
  })
  .get('/allocation', async (c) => {
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT ar.id, ar.billing_account_id, ar.strategy, ar.flat_amount_usd, ar.custom_multiplier,
              ar.effective_from, ar.effective_to, ar.created_at,
              ba.customer_id
       FROM billing.allocation_rules ar
       JOIN billing.billing_accounts ba ON ba.id = ar.billing_account_id
       WHERE ba.tenant_id = $1
       ORDER BY ar.effective_from DESC
       LIMIT 50`,
      [c.get('user').tenantId],
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, billingAccountId: r.billing_account_id, customerId: r.customer_id,
        strategy: r.strategy, flatAmountUsd: r.flat_amount_usd ? Number(r.flat_amount_usd) : null,
        customMultiplier: Number(r.custom_multiplier), effectiveFrom: r.effective_from,
        effectiveTo: r.effective_to, createdAt: r.created_at,
      })),
    });
  });
