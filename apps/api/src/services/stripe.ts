import { pool } from '../db/client';

/**
 * Stripe Mock 服务
 * 提供与 Stripe REST API 兼容的接口签名(Checkout/Customer/Subscription/Invoice/Webhook)
 * 真 Stripe 凭据就位时,只需替换 baseUrl + secret 即可切换
 *
 * 接口契约对齐 Stripe API v2024-06:
 *   stripe.checkout.sessions.create({...}) → { id, url }
 *   stripe.billingPortal.sessions.create({customer}) → { url }
 *   stripe.subscriptions.retrieve(id) → { id, status, items, current_period_end }
 *   stripe.invoices.list({customer}) → { data: [...] }
 *   stripe.webhooks.constructEvent(payload, signature, secret) → Event
 */

interface CheckoutLineItem {
  price_data?: { product_data?: { name: string }; unit_amount: number; currency: string };
  quantity?: number;
}

interface CheckoutSessionParams {
  customer_email: string;
  customer_id?: string;
  mode?: 'payment' | 'subscription';
  line_items: CheckoutLineItem[];
  success_url: string;
  cancel_url: string;
  metadata?: Record<string, string>;
  client_reference_id?: string;
}

interface CheckoutSession {
  id: string;
  url: string;
  customer: string;
  amount_total: number;
  currency: string;
  status: 'open' | 'complete' | 'expired';
  metadata: Record<string, string>;
  created: number;
}

interface PortalSessionParams {
  customer: string;
  return_url: string;
}

interface PortalSession {
  url: string;
}

interface Subscription {
  id: string;
  customer: string;
  status: 'active' | 'past_due' | 'canceled' | 'incomplete' | 'trialing';
  items: { data: Array<{ price: { id: string }; quantity: number }> };
  current_period_start: number;
  current_period_end: number;
  cancel_at_period_end: boolean;
  canceled_at: number | null;
  metadata: Record<string, string>;
}

interface Invoice {
  id: string;
  customer: string;
  subscription: string | null;
  number: string;
  status: 'draft' | 'open' | 'paid' | 'void' | 'uncollectible';
  amount_paid: number;
  amount_due: number;
  currency: string;
  period_start: number;
  period_end: number;
  created: number;
  paid_at: number | null;
  hosted_invoice_url: string;
  invoice_pdf: string;
}

interface WebhookEvent {
  id: string;
  type: string;
  data: { object: any };
  created: number;
}

const MOCK_CUSTOMERS = new Map<string, { id: string; email: string; metadata: Record<string, string> }>();
const MOCK_SUBSCRIPTIONS = new Map<string, Subscription>();
const MOCK_INVOICES: Invoice[] = [];
let eventCounter = 0;
const eventLog: WebhookEvent[] = [];

function now() { return Math.floor(Date.now() / 1000); }

function genId(prefix: string) {
  return `${prefix}_mock_${Math.random().toString(36).slice(2, 14)}`;
}

export const stripe = {
  checkout: {
    sessions: {
      async create(params: CheckoutSessionParams): Promise<CheckoutSession> {
        const total = (params.line_items ?? []).reduce((s, li) => {
          const amt = li.price_data?.unit_amount ?? 0;
          return s + amt * (li.quantity ?? 1);
        }, 0);
        const customer = params.customer_id ?? (() => {
          const c = { id: genId('cus'), email: params.customer_email, metadata: params.metadata ?? {} };
          MOCK_CUSTOMERS.set(c.id, c);
          return c.id;
        })();
        const id = genId('cs');
        const session: CheckoutSession = {
          id,
          url: `/billing/mock-checkout?session_id=${id}&success_url=${encodeURIComponent(params.success_url)}&cancel_url=${encodeURIComponent(params.cancel_url)}`,
          customer,
          amount_total: total,
          currency: 'usd',
          status: 'open',
          metadata: params.metadata ?? {},
          created: now(),
        };
        return session;
      },
    },
  },

  billingPortal: {
    sessions: {
      async create(params: PortalSessionParams): Promise<PortalSession> {
        return { url: `/billing/mock-portal?customer=${params.customer}&return_url=${encodeURIComponent(params.return_url)}` };
      },
    },
  },

  subscriptions: {
    async retrieve(id: string): Promise<Subscription | null> {
      return MOCK_SUBSCRIPTIONS.get(id) ?? null;
    },
    async update(id: string, params: { cancel_at_period_end?: boolean; metadata?: Record<string, string> }): Promise<Subscription | null> {
      const sub = MOCK_SUBSCRIPTIONS.get(id);
      if (!sub) return null;
      if (params.cancel_at_period_end !== undefined) sub.cancel_at_period_end = params.cancel_at_period_end;
      if (params.metadata) sub.metadata = { ...sub.metadata, ...params.metadata };
      return sub;
    },
  },

  invoices: {
    async list(params: { customer?: string }): Promise<{ data: Invoice[] }> {
      return { data: MOCK_INVOICES.filter((i) => !params.customer || i.customer === params.customer) };
    },
  },

  webhooks: {
    constructEvent(payload: string | Buffer, signature: string | null, secret: string): WebhookEvent {
      if (secret !== process.env.STRIPE_WEBHOOK_SECRET && secret !== 'whsec_mock_secret') {
        throw new Error('Invalid signature');
      }
      const event = typeof payload === 'string' ? JSON.parse(payload) : JSON.parse(payload.toString());
      eventLog.push(event);
      return event;
    },
  },

  _mock: {
    customers: MOCK_CUSTOMERS,
    subscriptions: MOCK_SUBSCRIPTIONS,
    invoices: MOCK_INVOICES,
    eventLog,
    reset() {
      MOCK_CUSTOMERS.clear();
      MOCK_SUBSCRIPTIONS.clear();
      MOCK_INVOICES.length = 0;
      eventLog.length = 0;
    },
  },
};

export async function applyWebhookEventToDb(event: WebhookEvent): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object as CheckoutSession & {
        subscription_id?: string;
        invoice_id?: string;
        customer_id?: string;
      };
      const tenantId = session.metadata?.tenant_id;
      const plan = session.metadata?.plan;
      if (!tenantId || !plan) throw new Error('Missing tenant_id/plan in metadata');

      if (session.subscription_id && session.customer_id) {
        const sub: Subscription = {
          id: session.subscription_id,
          customer: session.customer_id,
          status: 'active',
          items: { data: [{ price: { id: `price_${plan}` }, quantity: 1 }] },
          current_period_start: now(),
          current_period_end: now() + 30 * 86400,
          cancel_at_period_end: false,
          canceled_at: null,
          metadata: session.metadata,
        };
        MOCK_SUBSCRIPTIONS.set(sub.id, sub);

        await client.query(
          `UPDATE billing.billing_accounts
           SET plan = $1, status = 'active', updated_at = NOW()
           WHERE tenant_id = $2`,
          [plan, tenantId],
        );
        await client.query(
          `UPDATE core.tenants SET plan = $1::tenant_plan_enum, updated_at = NOW() WHERE id = $2`,
          [plan, tenantId],
        );
      }
    } else if (event.type === 'invoice.payment_succeeded') {
      const inv = event.data.object as Invoice;
      const subId = inv.subscription;
      MOCK_INVOICES.push(inv);
      if (subId) {
        const tenantId = MOCK_SUBSCRIPTIONS.get(subId)?.metadata?.tenant_id;
        if (tenantId) {
          await client.query(
            `INSERT INTO billing.invoices
               (tenant_id, customer_id, billing_account_id, invoice_number,
                period_start, period_end, subtotal_usd, tax_usd, total_usd,
                status, issued_at, paid_at)
             VALUES (
               $1, (SELECT id FROM core.customers WHERE tenant_id = $1 LIMIT 1),
               (SELECT id FROM billing.billing_accounts WHERE tenant_id = $1 LIMIT 1),
               $2, to_timestamp($3), to_timestamp($4), $5, 0, $5,
               'paid', to_timestamp($4), to_timestamp($4)
             )
             ON CONFLICT DO NOTHING`,
            [tenantId, inv.number, inv.period_start, inv.period_end, inv.amount_paid / 100],
          );
        }
      }
    } else if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object as Subscription;
      const tenantId = MOCK_SUBSCRIPTIONS.get(sub.id)?.metadata?.tenant_id;
      MOCK_SUBSCRIPTIONS.delete(sub.id);
      if (tenantId) {
        await client.query(
          `UPDATE billing.billing_accounts SET status = 'canceled', updated_at = NOW() WHERE tenant_id = $1`,
          [tenantId],
        );
      }
    } else if (event.type === 'customer.subscription.updated') {
      const sub = event.data.object as Subscription;
      const existing = MOCK_SUBSCRIPTIONS.get(sub.id);
      if (existing) {
        existing.status = sub.status;
        existing.cancel_at_period_end = sub.cancel_at_period_end;
      }
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET ?? 'whsec_mock_secret';

export function signWebhookPayload(payload: string, secret: string = STRIPE_WEBHOOK_SECRET): string {
  return `t=${now()},v1=${Buffer.from(secret + payload).toString('base64').slice(0, 32)}`;
}
