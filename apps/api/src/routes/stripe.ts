import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';
import { stripe, applyWebhookEventToDb, STRIPE_WEBHOOK_SECRET, signWebhookPayload } from '../services/stripe';

const checkoutSchema = z.object({
  plan: z.enum(['starter', 'pro', 'enterprise']),
  success_url: z.string().url(),
  cancel_url: z.string().url(),
});

export const stripeRoutes = new Hono()
  .post('/checkout', async (c) => {
    const user = c.get('user') as any;
    const body = await c.req.json().catch(() => null);
    const parsed = checkoutSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'Invalid body' } }, 400);

    const pg = (c as any).get('pg');
    const { rows: planRows } = await pg.query(
      `SELECT id, code, display_name, price_usd FROM billing.plans WHERE code = $1 AND status = 'active'`,
      [parsed.data.plan],
    );
    if (planRows.length === 0) return c.json({ error: { code: 'not_found', message: 'Plan not found' } }, 404);
    const plan = planRows[0];

    const session = await stripe.checkout.sessions.create({
      customer_email: user.email,
      mode: 'subscription',
      line_items: [{
        price_data: { product_data: { name: plan.display_name }, unit_amount: Math.round(Number(plan.price_usd) * 100), currency: 'usd' },
        quantity: 1,
      }],
      success_url: parsed.data.success_url,
      cancel_url: parsed.data.cancel_url,
      metadata: { tenant_id: user.tenantId, plan: plan.code, user_id: user.id },
      client_reference_id: user.tenantId,
    });

    const event = {
      id: 'evt_' + Math.random().toString(36).slice(2, 14),
      type: 'checkout.session.created',
      data: { object: session },
      created: Math.floor(Date.now() / 1000),
    };
    const sig = signWebhookPayload(JSON.stringify(event));
    return c.json({
      checkoutId: session.id,
      url: session.url,
      signature: sig,
      demoNote: 'In production, this URL is on Stripe. In mock mode, open in same tab and call /mock-confirm to simulate webhook.',
    }, 201);
  })

  .post('/portal', async (c) => {
    const user = c.get('user') as any;
    const pg = (c as any).get('pg');
    const body = await c.req.json().catch(() => ({}));
    const returnUrl = (body as { return_url?: string })?.return_url ?? '/billing';
    const { rows: customerRows } = await pg.query(
      `SELECT id FROM core.customers WHERE tenant_id = $1 LIMIT 1`,
      [user.tenantId],
    );
    const customer = customerRows[0]?.id ?? `cus_mock_${user.tenantId.slice(0, 8)}`;
    const portal = await stripe.billingPortal.sessions.create({
      customer,
      return_url: returnUrl,
    });
    return c.json({ url: portal.url });
  })

  .post('/webhook', async (c) => {
    const signature = c.req.header('stripe-signature');
    const rawBody = await c.req.text();
    try {
      const event = stripe.webhooks.constructEvent(rawBody, signature ?? null, STRIPE_WEBHOOK_SECRET);
      await applyWebhookEventToDb(event);
      return c.json({ received: true, eventId: event.id, type: event.type });
    } catch (err: any) {
      return c.json({ error: { code: 'webhook_error', message: err.message } }, 400);
    }
  })

  .get('/subscription', async (c) => {
    const user = c.get('user') as any;
    const pg = (c as any).get('pg');
    const { rows: billingRows } = await pg.query(
      `SELECT ba.plan, ba.status, ba.monthly_token_quota, ba.balance_usd, ba.current_period_start, ba.current_period_end
       FROM billing.billing_accounts ba WHERE ba.tenant_id = $1 LIMIT 1`,
      [user.tenantId],
    );
    if (billingRows.length === 0) return c.json({ subscription: null });
    const b = billingRows[0];
    return c.json({
      subscription: {
        plan: b.plan,
        status: b.status,
        monthlyTokenQuota: Number(b.monthly_token_quota),
        balanceUsd: Number(b.balance_usd),
        currentPeriodStart: b.current_period_start,
        currentPeriodEnd: b.current_period_end,
      },
    });
  })

  .get('/invoices', async (c) => {
    const user = c.get('user') as any;
    const pg = (c as any).get('pg');
    const { rows } = await pg.query(
      `SELECT id, invoice_number, subtotal_usd, tax_usd, total_usd, status,
              issued_at, paid_at, period_start, period_end
       FROM billing.invoices
       WHERE tenant_id = $1
       ORDER BY issued_at DESC NULLS LAST
       LIMIT 50`,
      [user.tenantId],
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, invoiceNumber: r.invoice_number,
        subtotalUsd: Number(r.subtotal_usd), taxUsd: Number(r.tax_usd), totalUsd: Number(r.total_usd),
        status: r.status, issuedAt: r.issued_at, paidAt: r.paid_at,
        periodStart: r.period_start, periodEnd: r.period_end,
      })),
    });
  })

  .post('/mock-confirm', async (c) => {
    const body = await c.req.json().catch(() => null) as { sessionId?: string; tenantId?: string; plan?: string } | null;
    if (!body?.sessionId || !body.tenantId || !body.plan) {
      return c.json({ error: { code: 'bad_request' } }, 400);
    }
    const subId = `sub_mock_${Math.random().toString(36).slice(2, 12)}`;
    const invId = `in_mock_${Math.random().toString(36).slice(2, 12)}`;
    const pg = (c as any).get('pg');
    const { rows: planRows } = await pg.query(`SELECT price_usd FROM billing.plans WHERE code = $1`, [body.plan]);
    const amount = planRows[0] ? Number(planRows[0].price_usd) * 100 : 9900;
    const now = Math.floor(Date.now() / 1000);

    const e1 = stripe.webhooks.constructEvent(
      JSON.stringify({
        id: 'evt_' + Math.random().toString(36).slice(2, 14),
        type: 'checkout.session.completed',
        data: {
          object: {
            id: body.sessionId,
            customer: 'cus_mock_' + body.tenantId.slice(0, 8),
            subscription_id: subId,
            invoice_id: invId,
            customer_id: 'cus_mock_' + body.tenantId.slice(0, 8),
            metadata: { tenant_id: body.tenantId, plan: body.plan, user_id: 'mock' },
            amount_total: amount,
            currency: 'usd',
            status: 'complete',
            created: now,
          },
        },
        created: now,
      }),
      null,
      STRIPE_WEBHOOK_SECRET,
    );
    await applyWebhookEventToDb(e1);

    const e2 = stripe.webhooks.constructEvent(
      JSON.stringify({
        id: 'evt_' + Math.random().toString(36).slice(2, 14),
        type: 'invoice.payment_succeeded',
        data: {
          object: {
            id: invId, customer: 'cus_mock_' + body.tenantId.slice(0, 8), subscription: subId,
            number: 'INV-MOCK-' + Date.now(),
            status: 'paid', amount_paid: amount, amount_due: 0, currency: 'usd',
            period_start: now, period_end: now + 30 * 86400, created: now, paid_at: now,
            hosted_invoice_url: '/billing/mock-invoice', invoice_pdf: '/billing/mock-invoice.pdf',
          },
        },
        created: now,
      }),
      null,
      STRIPE_WEBHOOK_SECRET,
    );
    await applyWebhookEventToDb(e2);

    return c.json({ ok: true, subscriptionId: subId, invoiceId: invId });
  });

export const STRIPE_PUBLIC_KEY = process.env.STRIPE_PUBLIC_KEY ?? 'pk_test_mock';
