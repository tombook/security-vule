import { Hono } from 'hono';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { createHash, randomBytes } from 'node:crypto';
import { pool } from '../db/client';
import { signAccessToken, verifyAccessToken } from '../middleware/auth';
import { badRequest, locked, notFound, unauthorized, ApiError } from '../middleware/error';
import { config } from '../config';

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MIN = 15;

export const authRoutes = new Hono()
  .post('/login', async (c) => {
    const body = await c.req.json().catch(() => null);
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success) throw badRequest('Invalid email or password format');
    const { email, password } = parsed.data;

    const client = await pool.connect();
    try {
      const { rows } = await client.query(
        `SELECT id, tenant_id, customer_id, email, password_hash, full_name, role, status, portal,
                failed_login_count, locked_until
         FROM core.users
         WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
         LIMIT 1`,
        [email],
      );

      // 防枚举:无论用户是否存在,统一响应时长(此处简化为同样的错误码)
      if (rows.length === 0) {
        throw unauthorized('Invalid email or password');
      }
      const user = rows[0];

      if (user.status === 'locked' && user.locked_until && new Date(user.locked_until) > new Date()) {
        const minutes = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60000);
        throw new ApiError(423, 'account_locked', `Account locked, retry in ${minutes} minutes`);
      }

      if (user.status === 'disabled') {
        throw new ApiError(403, 'account_disabled', 'Account has been disabled');
      }

      if (user.status === 'pending') {
        throw new ApiError(403, 'account_pending', 'Account is pending activation');
      }

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) {
        const newCount = (user.failed_login_count ?? 0) + 1;
        const shouldLock = newCount >= MAX_FAILED_ATTEMPTS;
        await client.query(
          `UPDATE core.users
             SET failed_login_count = $1,
                 locked_until = CASE WHEN $2 THEN NOW() + INTERVAL '${LOCK_DURATION_MIN} minutes' ELSE locked_until END,
                 status = CASE WHEN $2 THEN 'locked'::user_status_enum ELSE status END
           WHERE id = $3`,
          [newCount, shouldLock, user.id],
        );
        throw unauthorized('Invalid email or password');
      }

      await client.query(
        `UPDATE core.users SET failed_login_count = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1`,
        [user.id],
      );
      await client.query(
        `INSERT INTO core.sessions (user_id, tenant_id, user_agent, ip_address, expires_at)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')`,
        [user.id, user.tenant_id, c.req.header('User-Agent') ?? null, c.req.header('X-Forwarded-For') ?? null],
      );

      // 签 JWT
      const access_token = await signAccessToken({
        sub: user.id,
        email: user.email,
        role: user.role,
        tenant_id: user.tenant_id,
        portal: user.portal,
        customer_id: user.customer_id ?? undefined,
      });

      return c.json({
        access_token,
        user: {
          id: user.id,
          email: user.email,
          full_name: user.full_name,
          role: user.role,
          tenant_id: user.tenant_id,
          customer_id: user.customer_id,
        },
      });
    } finally {
      client.release();
    }
  })

  // GET /api/auth/me
  .get('/me', async (c) => {
    const auth = c.req.header('Authorization');
    if (!auth?.startsWith('Bearer ')) throw unauthorized();
    const payload = await verifyAccessToken(auth.slice(7));
    const client = await pool.connect();
    try {
      const { rows } = await client.query(
        `SELECT id, email, full_name, role, tenant_id, customer_id, status, portal
         FROM core.users WHERE id = $1 AND deleted_at IS NULL`,
        [payload.sub],
      );
      if (rows.length === 0) throw unauthorized('User not found');
      return c.json(rows[0]);
    } finally {
      client.release();
    }
  })

  .post('/logout', async (c) => {
    return c.json({ success: true });
  })

  .post('/forgot', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const schema = z.object({ email: z.string().email() });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request' } }, 400);

    const { rows } = await pool.query(
      `SELECT id, tenant_id, email FROM core.users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`,
      [parsed.data.email],
    );
    if (rows.length > 0) {
      const userId = rows[0].id;
      const tenantId = rows[0].tenant_id;
      const token = randomBytes(32).toString('hex');
      const tokenHash = createHash('sha256').update(token).digest('hex');
      await pool.query(
        `INSERT INTO core.password_reset_tokens
           (tenant_id, user_id, token_hash, expires_at, requested_via)
         VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', 'web_form')`,
        [tenantId, userId, tokenHash],
      );
      console.log(`[forgot] reset link: /reset?token=${token}`);
    }
    return c.json({ ok: true, message: '如邮箱存在,重置链接 1 小时内有效' });
  })

  .post('/reset', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const schema = z.object({ token: z.string().min(32), newPassword: z.string().min(10).max(128) });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const tokenHash = createHash('sha256').update(parsed.data.token).digest('hex');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `SELECT user_id, expires_at, used_at FROM core.password_reset_tokens
         WHERE token_hash = $1 FOR UPDATE`,
        [tokenHash],
      );
      if (rows.length === 0) {
        await client.query('ROLLBACK');
        throw notFound('Token 无效');
      }
      const t = rows[0];
      if (t.used_at) {
        await client.query('ROLLBACK');
        throw new ApiError(410, 'token_used', 'Token 已使用');
      }
      if (new Date(t.expires_at) < new Date()) {
        await client.query('ROLLBACK');
        throw new ApiError(410, 'token_expired', 'Token 已过期');
      }
      const newHash = await bcrypt.hash(parsed.data.newPassword, 12);
      await client.query(`UPDATE core.users SET password_hash = $1, failed_login_count = 0, locked_until = NULL WHERE id = $2`, [newHash, t.user_id]);
      await client.query(`UPDATE core.password_reset_tokens SET used_at = NOW() WHERE token_hash = $1`, [tokenHash]);
      await client.query(`UPDATE core.sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE user_id = $1`, [t.user_id]);
      await client.query('COMMIT');
      return c.json({ ok: true, message: '密码已更新,请重新登录' });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })

  .post('/invite/:token/accept', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const schema = z.object({ token: z.string().min(32), fullName: z.string().min(1).max(100), password: z.string().min(10) });
    const parsed = schema.safeParse({ token: c.req.param('token'), ...body });
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const tokenHash = createHash('sha256').update(parsed.data.token).digest('hex');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `SELECT id, tenant_id, customer_id, role, expires_at, status FROM core.invites
         WHERE token_hash = $1 FOR UPDATE`,
        [tokenHash],
      );
      if (rows.length === 0) {
        await client.query('ROLLBACK');
        throw notFound('邀请无效');
      }
      const inv = rows[0];
      if (inv.status !== 'pending') {
        await client.query('ROLLBACK');
        throw new ApiError(410, 'invite_used', '邀请已使用或已撤销');
      }
      if (new Date(inv.expires_at) < new Date()) {
        await client.query('ROLLBACK');
        throw new ApiError(410, 'invite_expired', '邀请已过期');
      }
      const passwordHash = await bcrypt.hash(parsed.data.password, 12);
      const { rows: userRows } = await client.query(
        `INSERT INTO core.users (tenant_id, customer_id, portal, email, password_hash, full_name, role, status, last_login_at)
         VALUES ($1, $2, $3, (SELECT email FROM core.invites WHERE id = $4), $5, $6, $7::user_role_enum, 'active', NOW())
         ON CONFLICT (tenant_id, email) DO UPDATE SET password_hash = EXCLUDED.password_hash, status = 'active', last_login_at = NOW(), full_name = EXCLUDED.full_name
         RETURNING id`,
        [inv.tenant_id, inv.customer_id, inv.role.startsWith('Provider') ? 'provider' : 'customer', inv.id, passwordHash, parsed.data.fullName, inv.role],
      );
      await client.query(`UPDATE core.invites SET status = 'accepted', accepted_at = NOW() WHERE id = $1`, [inv.id]);
      await client.query('COMMIT');
      return c.json({ ok: true, userId: userRows[0].id, message: '账号已激活,请登录' });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  });
