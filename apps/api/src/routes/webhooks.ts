import { Hono } from 'hono';
import { z } from 'zod';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { pool } from '../db/client';
import { notFound } from '../middleware/error';

const createSchema = z.object({
  url: z.string().url(),
  eventTypes: z.array(z.string()).min(1).default(['finding.created', 'finding.status_changed', 'scan.completed']),
  enabled: z.boolean().default(true),
});

function encryptSecret(plaintext: string): Buffer {
  const key = createHash('sha256').update(process.env.SOURCE_TOKEN_KMS_KEY ?? process.env.JWT_SECRET ?? 'dev').digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, enc, tag]);
}

export const webhooksRoutes = new Hono()
  .get('/', async (c) => {
    const user = c.get('user');
    const { rows } = await pool.query(
      `SELECT id, url, event_types, enabled, created_at,
              (SELECT count(*) FROM governance.webhook_deliveries WHERE webhook_id = w.id AND status = 'success')::int AS delivered_count,
              (SELECT count(*) FROM governance.webhook_deliveries WHERE webhook_id = w.id AND status = 'failed')::int AS failed_count,
              (SELECT max(delivered_at) FROM governance.webhook_deliveries WHERE webhook_id = w.id) AS last_delivered_at
       FROM governance.webhooks w
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [user.tenantId],
    );
    return c.json({ items: rows });
  })
  .post('/', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner' && user.role !== 'ProviderAdmin') {
      return c.json({ error: { code: 'forbidden' } }, 403);
    }
    const body = await c.req.json().catch(() => ({}));
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const secret = randomBytes(24).toString('hex');
    const enc = encryptSecret(secret);

    const { rows } = await pool.query(
      `INSERT INTO governance.webhooks
         (tenant_id, url, secret_ciphertext, event_types, enabled, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, url, event_types, enabled, created_at`,
      [user.tenantId, parsed.data.url, enc, parsed.data.eventTypes, parsed.data.enabled, user.id],
    );
    return c.json({ ...rows[0], secret, note: 'secret 仅在创建时显示一次,用于校验 HMAC 签名' }, 201);
  })
  .patch('/:id', async (c) => {
    const user = c.get('user');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const schema = createSchema.partial();
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request' } }, 400);

    const sets: string[] = [];
    const params: unknown[] = [];
    if (parsed.data.url !== undefined) { params.push(parsed.data.url); sets.push(`url = $${params.length}`); }
    if (parsed.data.eventTypes !== undefined) { params.push(parsed.data.eventTypes); sets.push(`event_types = $${params.length}`); }
    if (parsed.data.enabled !== undefined) { params.push(parsed.data.enabled); sets.push(`enabled = $${params.length}`); }
    if (!sets.length) return c.json({ error: { code: 'bad_request', message: '无字段更新' } }, 400);
    sets.push('updated_at = NOW()');
    params.push(id, user.tenantId);
    const { rows } = await pool.query(
      `UPDATE governance.webhooks SET ${sets.join(', ')}
       WHERE id = $${params.length - 1} AND tenant_id = $${params.length}
       RETURNING id, url, enabled`,
      params,
    );
    if (!rows.length) throw notFound('webhook 不存在');
    return c.json(rows[0]);
  })
  .delete('/:id', async (c) => {
    const user = c.get('user');
    const id = c.req.param('id');
    const { rows } = await pool.query(
      `UPDATE governance.webhooks SET enabled = false, deleted_at = NOW()
       WHERE id = $1 AND tenant_id = $2
       RETURNING id, enabled`,
      [id, user.tenantId],
    );
    if (!rows.length) throw notFound('webhook 不存在');
    return c.json({ disabled: rows[0] });
  })
  .post('/:id/test', async (c) => {
    const user = c.get('user');
    const id = c.req.param('id');
    const { rows } = await pool.query(
      `SELECT url FROM governance.webhooks WHERE id = $1 AND tenant_id = $2 AND enabled = true`,
      [id, user.tenantId],
    );
    if (!rows.length) throw notFound('webhook 不存在');
    const start = Date.now();
    try {
      const res = await fetch(rows[0].url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Security-Vule-Test': 'true' },
        body: JSON.stringify({ event: 'test.ping', sent_at: new Date().toISOString() }),
      });
      await pool.query(
        `INSERT INTO governance.webhook_deliveries
           (webhook_id, event_type, payload, attempt, status, http_status, response_body, duration_ms, delivered_at)
         SELECT $1, 'test.ping', $2, 1, $3, $4, $5, $6, NOW()`,
        [id, JSON.stringify({ event: 'test.ping' }), res.status < 400 ? 'success' : 'failed',
         res.status, (await res.text()).slice(0, 500), Date.now() - start],
      );
      return c.json({ ok: res.status < 400, httpStatus: res.status, latencyMs: Date.now() - start });
    } catch (err: any) {
      return c.json({ ok: false, error: err.message, latencyMs: Date.now() - start });
    }
  });