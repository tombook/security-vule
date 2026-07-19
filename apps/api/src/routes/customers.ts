import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';
import { notFound } from '../middleware/error';
import { requireRole, PROVIDER_ADMIN_ROLES, PROVIDER_WRITE_ROLES } from '../middleware/rbac';

const querySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  size: z.coerce.number().int().min(1).max(100).default(20),
  q: z.string().optional(),
  status: z.enum(['active', 'suspended', 'deleted']).optional(),
});

const createSchema = z.object({
  name: z.string().min(1).max(200),
  slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/).optional(),
  contactEmail: z.string().email().optional(),
  contactPhone: z.string().max(50).optional(),
  industry: z.string().max(100).optional(),
  slaTier: z.enum(['standard', 'priority', 'enterprise']).default('standard'),
});

const patchSchema = createSchema.partial().extend({
  status: z.enum(['active', 'suspended']).optional(),
});

export const customerRoutes = new Hono()
  .get('/', async (c) => {
    const url = new URL(c.req.url);
    const raw = Object.fromEntries(url.searchParams.entries());
    const parsed = querySchema.safeParse(raw);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'Invalid query' } }, 400);
    const { page, size, q, status } = parsed.data;
    const offset = (page - 1) * size;

    const pg = c.get('pg');

    const where: string[] = ['deleted_at IS NULL'];
    const params: unknown[] = [];
    if (q) {
      params.push(`%${q}%`);
      where.push(`name ILIKE $${params.length}`);
    }
    if (status) {
      params.push(status);
      where.push(`status = $${params.length}::customer_status_enum`);
    }
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

    params.push(size, offset);
    const itemsRes = await pg.query(
      `SELECT id, name, status, contact_email, contact_phone, white_label, created_at
       FROM core.customers ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );

    const countRes = await pg.query(
      `SELECT count(*)::int AS total FROM core.customers ${whereClause}`,
      params.slice(0, params.length - 2),
    );

    return c.json({
      items: itemsRes.rows,
      total: countRes.rows[0]?.total ?? 0,
      page,
      size,
    });
  })
  .get('/:id', async (c) => {
    const id = c.req.param('id');
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, name, slug, status, contact_email, contact_phone, industry, sla_tier,
              billing_account_id, white_label, created_at, updated_at
       FROM core.customers
       WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    if (rows.length === 0) throw notFound('客户不存在');

    const [projectsRes, findingsRes, scansRes, billingRes] = await Promise.all([
      pg.query(`SELECT count(*)::int AS total FROM core.projects WHERE customer_id = $1 AND deleted_at IS NULL`, [id]),
      pg.query(`SELECT count(*)::int AS total FROM detection.findings WHERE customer_id = $1`, [id]),
      pg.query(`SELECT count(*)::int AS total FROM detection.scan_runs WHERE customer_id = $1`, [id]),
      pool.query(
        `SELECT id, plan, monthly_token_quota, balance_usd, status
         FROM billing.billing_accounts WHERE customer_id = $1`,
        [id],
      ),
    ]);

    return c.json({
      ...rows[0],
      counts: {
        projects: projectsRes.rows[0].total,
        findings: findingsRes.rows[0].total,
        scans: scansRes.rows[0].total,
      },
      billing: billingRes.rows[0] ?? null,
    });
  })
  .post('/', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner' && user.role !== 'ProviderAdmin') {
      return c.json({ error: { code: 'forbidden', message: '仅 Owner/Admin 可创建客户' } }, 403);
    }
    const body = await c.req.json().catch(() => null);
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const { name, slug, contactEmail, contactPhone, industry, slaTier } = parsed.data;
    const finalSlug = slug ?? name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 100);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const custRes = await client.query(
        `INSERT INTO core.customers (tenant_id, name, slug, contact_email, contact_phone, industry, sla_tier)
         VALUES ($1, $2, $3, $4, $5, $6, $7::sla_tier_enum)
         RETURNING id, name, slug, status, contact_email, industry, sla_tier, created_at`,
        [user.tenantId, name, finalSlug, contactEmail ?? null, contactPhone ?? null, industry ?? null, slaTier],
      );
      const customer = custRes.rows[0];

      const billingRes = await client.query(
        `INSERT INTO billing.billing_accounts
           (tenant_id, customer_id, plan, status, monthly_token_quota, balance_usd,
            current_period_start, current_period_end)
         VALUES ($1, $2, 'starter', 'active', 100000, 0.00, date_trunc('month', NOW()), (date_trunc('month', NOW()) + INTERVAL '1 month')::date)
         RETURNING id, plan, monthly_token_quota, balance_usd, status`,
        [user.tenantId, customer.id],
      );
      const billing = billingRes.rows[0];

      await client.query(
        `UPDATE core.customers SET billing_account_id = $1 WHERE id = $2`,
        [billing.id, customer.id],
      );
      await client.query('COMMIT');

      return c.json({ ...customer, billing }, 201);
    } catch (err: any) {
      await client.query('ROLLBACK');
      if (err.code === '23505') {
        return c.json({ error: { code: 'conflict', message: 'slug 已存在' } }, 409);
      }
      throw err;
    } finally {
      client.release();
    }
  })
  .patch('/:id', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner' && user.role !== 'ProviderAdmin') {
      return c.json({ error: { code: 'forbidden', message: '仅 Owner/Admin 可改客户' } }, 403);
    }
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);
    const parsed = patchSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const sets: string[] = [];
    const params: unknown[] = [];
    for (const [key, value] of Object.entries(parsed.data)) {
      if (value === undefined) continue;
      const col = key.replace(/[A-Z]/g, (m) => `_${m.toLowerCase()}`);
      // Enum columns need an inline cast because pg passes the
      // parameter as text by default. We append the cast to the
      // placeholder suffix in the SET clause (not the value).
      const cast =
        col === 'sla_tier' ? '::sla_tier_enum'
        : col === 'status' ? '::customer_status_enum'
        : '';
      params.push(value);
      sets.push(`${col} = $${params.length}${cast}`);
    }
    if (sets.length === 0) return c.json({ error: { code: 'bad_request', message: '无字段更新' } }, 400);

    sets.push('updated_at = NOW()');
    params.push(id);
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `UPDATE core.customers SET ${sets.join(', ')}
       WHERE id = $${params.length} AND deleted_at IS NULL
       RETURNING id, name, status, contact_email, sla_tier, updated_at`,
      params,
    );
    if (rows.length === 0) throw notFound('客户不存在');
    return c.json(rows[0]);
  })

  // ── Soft-delete customer ──────────────────────────
  // status='deleted' + deleted_at. The 90-day retention
  // window is enforced by a cleanup worker — this endpoint
  // only flips the flag.
  //
  // Cascade (same DB transaction):
  //   - core.projects under this customer → 'paused' + deleted_at
  //   - core.targets under this customer → 'retired'
  .delete('/:id', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner' && user.role !== 'ProviderAdmin') {
      return c.json({ error: { code: 'forbidden', message: '仅 Owner/Admin 可删除客户' } }, 403);
    }
    const id = c.req.param('id');
    const pg = c.get('pg');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const cust = await client.query(
        `SELECT id, name FROM core.customers
          WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
          FOR UPDATE`,
        [id, user.tenantId],
      );
      if (cust.rows.length === 0) {
        return c.json({ error: { code: 'not_found', message: '客户不存在或已删除' } }, 404);
      }
      await client.query(
        `UPDATE core.customers
           SET status = 'deleted'::customer_status_enum,
               deleted_at = NOW(),
               updated_at = NOW()
         WHERE id = $1`,
        [id],
      );
      await client.query(
        `UPDATE core.projects
           SET status = 'paused', deleted_at = NOW(), updated_at = NOW()
         WHERE customer_id = $1 AND deleted_at IS NULL`,
        [id],
      );
      await client.query(
        `UPDATE core.targets
           SET status = 'retired', updated_at = NOW()
         WHERE customer_id = $1 AND status != 'retired'`,
        [id],
      );
      await client.query('COMMIT');
      return c.json({
        ok: true,
        deleted: { id, name: cust.rows[0].name },
        cascade: { projects_paused: true, targets_retired: true },
      });
    } catch (err: any) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })
  .get('/:id/contacts', async (c) => {
    const id = c.req.param('id');
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, name, email, phone, role, is_primary, created_at
       FROM core.contacts
       WHERE customer_id = $1
       ORDER BY is_primary DESC, created_at ASC`,
      [id],
    );
    return c.json({ items: rows });
    })
    .post('/:id/contacts', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);
    const schema = z.object({
      name: z.string().min(1).max(100),
      email: z.string().email(),
      phone: z.string().max(50).optional(),
      role: z.enum(['primary', 'security', 'billing', 'engineering', 'other']).default('other'),
      isPrimary: z.boolean().default(false),
    });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const pg = c.get('pg');
    if (parsed.data.isPrimary) {
      await pg.query(`UPDATE core.contacts SET is_primary = false WHERE customer_id = $1`, [id]);
    }
    const { rows } = await pg.query(
      `INSERT INTO core.contacts (tenant_id, customer_id, name, email, phone, role, is_primary)
       VALUES ($1, $2, $3, $4, $5, $6::contact_role_enum, $7)
       RETURNING id, name, email, role, is_primary, created_at`,
      [c.get('user').tenantId, id, parsed.data.name, parsed.data.email, parsed.data.phone ?? null,
       parsed.data.role, parsed.data.isPrimary],
    );
    return c.json(rows[0], 201);
  });
