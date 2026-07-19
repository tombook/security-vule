import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';
import { badRequest, notFound } from '../middleware/error';

const querySchema = z.object({
  customerId: z.string().uuid().optional(),
  projectId: z.string().uuid().optional(),
  capability: z.enum(['poc_gen', 'triage', 'explain', 'report', 'monitor']).optional(),
  days: z.coerce.number().int().min(1).max(365).default(30),
});

export const usageRoutes = new Hono()
  .get('/usage', async (c) => {
    const user = c.get('user');
    const url = new URL(c.req.url);
    const raw = Object.fromEntries(url.searchParams.entries());
    const parsed = querySchema.safeParse(raw);
    if (!parsed.success) return c.json({ error: { code: 'bad_request' } }, 400);
    const { customerId, projectId, capability, days } = parsed.data;

    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

    const where: string[] = ['tenant_id = $1', 'occurred_at >= $2'];
    const params: unknown[] = [user.tenantId, since];
    if (customerId) { params.push(customerId); where.push(`customer_id = $${params.length}`); }
    if (projectId) { params.push(projectId); where.push(`project_id = $${params.length}`); }
    if (capability) { params.push(capability); where.push(`capability = $${params.length}::ai_capability_enum`); }
    const whereClause = `WHERE ${where.join(' AND ')}`;

    const summaryRes = await pool.query(
      `SELECT capability,
              count(*)::int AS calls,
              sum(prompt_tokens)::bigint AS prompt_tokens,
              sum(completion_tokens)::bigint AS completion_tokens,
              sum(total_tokens)::bigint AS total_tokens,
              sum(cost_usd)::numeric AS cost_usd
       FROM usage.usage_events
       ${whereClause}
       GROUP BY capability
       ORDER BY total_tokens DESC`,
      params,
    );

    const byCustomerRes = await pool.query(
      `SELECT COALESCE(c.name, 'Provider-direct') AS customer_name,
              COALESCE(ue.customer_id, '00000000-0000-0000-0000-000000000000') AS customer_id,
              count(*)::int AS calls,
              sum(ue.total_tokens)::bigint AS total_tokens,
              sum(ue.cost_usd)::numeric AS cost_usd
       FROM usage.usage_events ue
       LEFT JOIN core.customers c ON c.id = ue.customer_id
       WHERE ue.tenant_id = $1 AND ue.occurred_at >= $2
       GROUP BY c.name, ue.customer_id
       ORDER BY total_tokens DESC
       LIMIT 10`,
      [user.tenantId, since],
    );

    const dailyRes = await pool.query(
      `SELECT date_trunc('day', occurred_at)::date AS day,
              sum(total_tokens)::bigint AS total_tokens,
              sum(cost_usd)::numeric AS cost_usd
       FROM usage.usage_events
       ${whereClause}
       GROUP BY day
       ORDER BY day ASC`,
      params,
    );

    const planRes = await pool.query(
      `SELECT plan, monthly_token_quota, balance_usd
       FROM billing.billing_accounts
       WHERE tenant_id = $1 LIMIT 1`,
      [user.tenantId],
    );
    const plan = planRes.rows[0] ?? null;

    const totalTokens = summaryRes.rows.reduce((s, r) => s + Number(r.total_tokens), 0);
    const totalCost = summaryRes.rows.reduce((s, r) => s + Number(r.cost_usd ?? 0), 0);
    const quota = Number(plan?.monthly_token_quota ?? 0);
    const usagePercent = quota > 0 ? Math.round((totalTokens / quota) * 100) : 0;

    const optimizations: string[] = [];
    if (capability === undefined) {
      const pocGenRow = summaryRes.rows.find((r) => r.capability === 'poc_gen');
      if (pocGenRow && Number(pocGenRow.calls) > 100) {
        optimizations.push(`poc_gen 调用 ${pocGenRow.calls} 次,建议启用 PoC 库复用减少重复生成`);
      }
      const triageRow = summaryRes.rows.find((r) => r.capability === 'triage');
      if (triageRow && Number(triageRow.calls) > 200) {
        optimizations.push(`triage 调用频繁,建议调整策略让低严重度跳过 AI 预筛`);
      }
      if (usagePercent > 80) {
        optimizations.push(`本月用量已达 ${usagePercent}%,建议升级套餐或购买超额配额`);
      }
    }

    return c.json({
      period: { days, since },
      totals: {
        calls: summaryRes.rows.reduce((s, r) => s + r.calls, 0),
        totalTokens,
        totalCostUsd: Number(totalCost.toFixed(4)),
      },
      plan: plan ? { plan: plan.plan, monthlyQuota: quota, balanceUsd: plan.balance_usd } : null,
      usagePercent,
      byCapability: summaryRes.rows.map((r) => ({
        capability: r.capability,
        calls: r.calls,
        promptTokens: Number(r.prompt_tokens),
        completionTokens: Number(r.completion_tokens),
        totalTokens: Number(r.total_tokens),
        costUsd: Number(r.cost_usd ?? 0),
      })),
      topCustomers: byCustomerRes.rows.map((r) => ({
        customerId: r.customer_id,
        customerName: r.customer_name,
        calls: r.calls,
        totalTokens: Number(r.total_tokens),
        costUsd: Number(r.cost_usd ?? 0),
      })),
      dailySeries: dailyRes.rows.map((r) => ({
        day: r.day,
        totalTokens: Number(r.total_tokens),
        costUsd: Number(r.cost_usd ?? 0),
      })),
      optimizations,
    });
  })
  .get('/customers/:id/billing', async (c) => {
    const user = c.get('user');
    const customerId = c.req.param('id');
    const { rows: customer } = await pool.query(
      `SELECT c.id, c.name, c.sla_tier, ba.plan, ba.monthly_token_quota, ba.balance_usd, ba.status
       FROM core.customers c
       LEFT JOIN billing.billing_accounts ba ON ba.customer_id = c.id
       WHERE c.id = $1 AND c.tenant_id = $2`,
      [customerId, user.tenantId],
    );
    if (!customer.length) throw notFound('客户不存在');
    const c_row = customer[0];

    const usageRes = await pool.query(
      `SELECT date_trunc('month', occurred_at)::date AS month,
              count(*)::int AS calls,
              sum(total_tokens)::bigint AS total_tokens,
              sum(cost_usd)::numeric AS cost_usd
       FROM usage.usage_events
       WHERE tenant_id = $1 AND customer_id = $2
         AND occurred_at >= date_trunc('month', NOW())
       GROUP BY month`,
      [user.tenantId, customerId],
    );

    const allocationRes = await pool.query(
      `SELECT ar.strategy, ar.flat_amount_usd, ar.custom_multiplier
       FROM billing.allocation_rules ar
       JOIN billing.billing_accounts ba ON ba.id = ar.billing_account_id
       WHERE ba.customer_id = $1 LIMIT 1`,
      [customerId],
    );

    const invRes = await pool.query(
      `SELECT id, invoice_number, period_start, period_end, subtotal_usd, tax_usd, total_usd, status
       FROM billing.invoices
       WHERE tenant_id = $1 AND customer_id = $2
       ORDER BY created_at DESC LIMIT 5`,
      [user.tenantId, customerId],
    );

    return c.json({
      customer: c_row,
      currentMonthUsage: usageRes.rows[0] ?? { calls: 0, totalTokens: 0, costUsd: 0 },
      allocationRule: allocationRes.rows[0] ?? null,
      recentInvoices: invRes.rows,
    });
  })
  .get('/customers/:id/quotas', async (c) => {
    const user = c.get('user');
    const customerId = c.req.param('id');
    const { rows } = await pool.query(
      `SELECT id, capability, monthly_token_limit, alert_threshold, effective_from
       FROM usage.quota_policies
       WHERE tenant_id = $1 AND (customer_id = $2 OR customer_id IS NULL)
       ORDER BY customer_id NULLS LAST, capability`,
      [user.tenantId, customerId],
    );
    return c.json({ items: rows });
  });