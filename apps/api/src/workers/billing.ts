// apps/api/src/workers/billing.ts
// P5.1 月结 worker — 自然月 1 号 00:00 自动生成 invoice

import { pool } from '../db/client';

export async function runMonthlyBilling(targetMonth?: Date): Promise<{ invoicesCreated: number; tenants: number }> {
  const target = targetMonth ?? new Date(new Date().getFullYear(), new Date().getMonth() - 1, 1);
  const periodStart = new Date(target.getFullYear(), target.getMonth(), 1).toISOString().slice(0, 10);
  const periodEnd = new Date(target.getFullYear(), target.getMonth() + 1, 0).toISOString().slice(0, 10);
  console.log(`[monthly-billing] processing period ${periodStart} ~ ${periodEnd}`);

  const tenants = await pool.query(`SELECT id FROM core.tenants WHERE status = 'active'`);
  let invoicesCreated = 0;

  for (const t of tenants.rows) {
    const tenantsId = t.id;
    const customerAccounts = await pool.query(
      `SELECT id, customer_id, plan, monthly_token_quota
       FROM billing.billing_accounts
       WHERE tenant_id = $1`,
      [tenantsId],
    );

    for (const acc of customerAccounts.rows) {
      const usageRes = await pool.query(
        `SELECT count(*)::int AS calls, COALESCE(sum(total_tokens), 0)::bigint AS tokens,
                COALESCE(sum(cost_usd), 0)::numeric AS cost
         FROM usage.usage_events
         WHERE tenant_id = $1 AND customer_id = $2
           AND occurred_at >= $3::date AND occurred_at < ($3::date + INTERVAL '1 month')`,
        [tenantsId, acc.customer_id, periodStart],
      );
      const usage = usageRes.rows[0];
      const quota = Number(acc.monthly_token_quota);
      const tokens = Number(usage.tokens);
      const overage = Math.max(0, tokens - quota);

      const { rows: ruleRows } = await pool.query(
        `SELECT ar.strategy, ar.flat_amount_usd, ar.custom_multiplier
         FROM billing.allocation_rules ar WHERE ar.billing_account_id = $1`,
        [acc.id],
      );
      const rule = ruleRows[0];
      const planFee = await pool.query(
        `SELECT price_usd FROM billing.plans WHERE code = $1`,
        [acc.plan],
      );
      const planCost = Number(planFee.rows[0]?.price_usd ?? 0);
      const overageCost = overage * 0.00002;

      const subtotal = planCost + overageCost;
      const tax = subtotal * 0.06;
      const total = subtotal + tax;

      await pool.query(
        `INSERT INTO billing.invoices
           (tenant_id, customer_id, billing_account_id, invoice_number,
            period_start, period_end, subtotal_usd, tax_usd, total_usd,
            plan_fee_usd, overage_tokens, overage_usd, status, issued_at, paid_at)
         VALUES ($1, $2, $3, $4, $5::date, $6::date, $7, $8, $9, $10, $11, $12, 'pending', NOW(), NULL)
         ON CONFLICT (tenant_id, customer_id, period_start) DO UPDATE SET
            subtotal_usd = EXCLUDED.subtotal_usd, tax_usd = EXCLUDED.tax_usd,
            total_usd = EXCLUDED.total_usd
         RETURNING id`,
        [
          tenantsId, acc.customer_id, acc.id,
          `INV-${tenantsId.slice(0, 8)}-${periodStart.replace(/-/g, '')}-${acc.id.slice(0, 8)}`,
          periodStart, periodEnd, subtotal.toFixed(2), tax.toFixed(2), total.toFixed(2),
          planCost, overage, overageCost.toFixed(2),
        ],
      );
      invoicesCreated++;
    }
  }
  console.log(`[monthly-billing] done: ${invoicesCreated} invoices for ${tenants.rows.length} tenants`);
  return { invoicesCreated, tenants: tenants.rows.length };
}

let monthlyTimer: NodeJS.Timeout | null = null;
let monthlyBusy = false;

export function startMonthlyBillingWorker(): void {
  if (monthlyTimer) return;

  const tick = () => {
    // Poll every 5 minutes instead of one giant setTimeout. Reason:
    // Node.js (and Bun's wrapper) caps setTimeout's 32-bit signed
    // integer delay at ~24.8 days; anything longer triggers
    //   TimeoutOverflowWarning: <ms> does not fit into a 32-bit
    //                           signed integer. Timeout duration was
    //                           set to 1.
    // which silently clamps the wait to 1ms, causing the worker to
    // fire immediately on the next tick and produce a tight loop.
    // Polling short, well-known delays avoids that entirely.
    monthlyTimer = setInterval(async () => {
      if (monthlyBusy) return;
      const now = new Date();
      // Fire at the 5-minute mark of the 1st of each month.
      if (now.getDate() === 1 && now.getHours() === 0 && now.getMinutes() < 5) {
        monthlyBusy = true;
        try { await runMonthlyBilling(); }
        catch (err) { console.error('[monthly-billing] error', err); }
        finally { monthlyBusy = false; }
      }
    }, 5 * 60 * 1000);
    const next = nextRunAt(new Date());
    console.log(`[monthly-billing] next run at ${next.toISOString()}`);
  };

  tick();
}

/** 1st of next month, 00:05:00 — when the monthly billing should fire. */
export function nextRunAt(now: Date): Date {
  return new Date(now.getFullYear(), now.getMonth() + 1, 1, 0, 5, 0);
}

export function stopMonthlyBillingWorker(): void {
  if (monthlyTimer) { clearInterval(monthlyTimer); monthlyTimer = null; }
  monthlyBusy = false;
}