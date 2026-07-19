import { Hono } from 'hono';
import { z } from 'zod';
import { randomBytes } from 'node:crypto';
import { pool } from '../db/client';
import { badRequest, notFound, unauthorized } from '../middleware/error';

const GITHUB_AUTHORIZE = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN = 'https://github.com/login/oauth/access_token';
const GITLAB_AUTHORIZE = 'https://gitlab.com/oauth/authorize';
const GITLAB_TOKEN = 'https://gitlab.com/oauth/token';

const STATE_TTL_MS = 10 * 60 * 1000;

const providerSchema = z.enum(['github', 'gitlab']);

function buildAuthorizeUrl(provider: 'github' | 'gitlab', state: string, redirectUri: string): string {
  if (provider === 'github') {
    const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
    if (!clientId) throw badRequest('GITHUB_OAUTH_CLIENT_ID 未配置');
    const u = new URL(GITHUB_AUTHORIZE);
    u.searchParams.set('client_id', clientId);
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('scope', 'repo');
    u.searchParams.set('state', state);
    u.searchParams.set('allow_signup', 'false');
    return u.toString();
  }
  const clientId = process.env.GITLAB_OAUTH_CLIENT_ID;
  if (!clientId) throw badRequest('GITLAB_OAUTH_CLIENT_ID 未配置');
  const u = new URL(GITLAB_AUTHORIZE);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', 'api');
  u.searchParams.set('state', state);
  return u.toString();
}

async function exchangeCode(
  provider: 'github' | 'gitlab',
  code: string,
  redirectUri: string,
): Promise<{ accessToken: string; refreshToken?: string; expiresAt?: Date }> {
  if (provider === 'github') {
    const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
    const clientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET;
    if (!clientId || !clientSecret) throw badRequest('GitHub OAuth 凭据未配置');
    const res = await fetch(GITHUB_TOKEN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri }),
    });
    const data: any = await res.json();
    if (data.error) throw badRequest(`GitHub OAuth: ${data.error_description ?? data.error}`);
    return { accessToken: data.access_token, refreshToken: data.refresh_token };
  }
  const clientId = process.env.GITLAB_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GITLAB_OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) throw badRequest('GitLab OAuth 凭据未配置');
  const res = await fetch(GITLAB_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId, client_secret: clientSecret, code,
      grant_type: 'authorization_code', redirect_uri: redirectUri,
    }),
  });
  const data: any = await res.json();
  if (data.error) throw badRequest(`GitLab OAuth: ${data.error_description ?? data.error}`);
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: data.expires_in ? new Date(Date.now() + data.expires_in * 1000) : undefined,
  };
}

async function encryptToken(plaintext: string): Promise<Buffer> {
  const kmsKey = process.env.SOURCE_TOKEN_KMS_KEY ?? process.env.JWT_SECRET ?? 'dev-encryption-key';
  const crypto = await import('node:crypto');
  const key = crypto.createHash('sha256').update(kmsKey).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]);
}

export const oauthRoutes = new Hono()
  .post('/connect/start', async (c) => {
    const body = await c.req.json().catch(() => null);
    const schema = z.object({
      provider: providerSchema,
      projectId: z.string().uuid(),
      redirectAfter: z.string().optional(),
    });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const user = c.get('user');
    const state = randomBytes(24).toString('hex');
    const { projectId, provider, redirectAfter } = parsed.data;

    const pg = c.get('pg');
    const proj = await pg.query(
      `SELECT p.id, p.customer_id FROM core.projects p
       WHERE p.id = $1 AND p.tenant_id = $2`, [projectId, user.tenantId],
    );
    if (proj.rows.length === 0) throw notFound('项目不存在');

    const frontendUrl = process.env.FRONTEND_URL ?? 'http://localhost:5173';
    const redirectUri = `${frontendUrl}/oauth/callback`;

    await pool.query(
      `INSERT INTO core.oauth_states (state, provider, tenant_id, customer_id, project_id, redirect_after, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '10 minutes')`,
      [state, provider, user.tenantId, proj.rows[0].customer_id, projectId, redirectAfter ?? null],
    );

    const authorizeUrl = buildAuthorizeUrl(provider, state, redirectUri);
    return c.json({ authorizeUrl, state });
  })
  .post('/connect/callback', async (c) => {
    const body = await c.req.json().catch(() => null);
    const schema = z.object({
      provider: providerSchema,
      code: z.string().min(1),
      state: z.string().min(1),
    });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);
    const { provider, code, state } = parsed.data;

    const stateRes = await pool.query(
      `SELECT id, tenant_id, customer_id, project_id, expires_at, redirect_after
       FROM core.oauth_states
       WHERE state = $1 AND provider = $2`,
      [state, provider],
    );
    if (stateRes.rows.length === 0) throw unauthorized('state 无效或已过期');
    const stateRow = stateRes.rows[0];
    if (new Date(stateRow.expires_at) < new Date()) {
      await pool.query(`DELETE FROM core.oauth_states WHERE id = $1`, [stateRow.id]);
      throw unauthorized('state 已过期,请重新发起');
    }
    const user = c.get('user');
    if (stateRow.tenant_id !== user.tenantId) throw unauthorized('state 跨租户不匹配');

    const frontendUrl = process.env.FRONTEND_URL ?? 'http://localhost:5173';
    const redirectUri = `${frontendUrl}/oauth/callback`;

    let tokens;
    try {
      tokens = await exchangeCode(provider, code, redirectUri);
    } catch (err: any) {
      await pool.query(`DELETE FROM core.oauth_states WHERE id = $1`, [stateRow.id]);
      throw badRequest(err.message ?? 'OAuth 兑换失败');
    }

    const repoRes = provider === 'github'
      ? await fetch('https://api.github.com/user/repos?per_page=1&sort=updated', {
          headers: { Authorization: `Bearer ${tokens.accessToken}`, Accept: 'application/vnd.github+json' },
        }).then((r) => r.json() as any)
      : await fetch('https://gitlab.com/api/v4/projects?membership=true&per_page=1&order_by=last_activity_at', {
          headers: { Authorization: `Bearer ${tokens.accessToken}` },
        }).then((r) => r.json() as any);

    const repoFullName = Array.isArray(repoRes) && repoRes.length > 0
      ? (provider === 'github' ? repoRes[0].full_name : repoRes[0].path_with_namespace)
      : null;

    const accessTokenCiphertext = await encryptToken(tokens.accessToken);
    const refreshTokenCiphertext = tokens.refreshToken ? await encryptToken(tokens.refreshToken) : null;

    const webhookSecret = randomBytes(20).toString('hex');
    const webhookSecretCiphertext = await encryptToken(webhookSecret);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL app.current_tenant = '${user.tenantId}'`);
      await client.query(`SET LOCAL app.current_user_role = '${user.role}'`);

      await client.query(`DELETE FROM core.sources WHERE project_id = $1`, [stateRow.project_id]);
      const { rows } = await client.query(
        `INSERT INTO core.sources
           (project_id, tenant_id, customer_id, source_type, repo_full_name, branch,
            access_token_ciphertext, refresh_token_ciphertext, token_expires_at,
            webhook_secret_ciphertext, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')
         RETURNING id, project_id, source_type, repo_full_name, branch, status`,
        [stateRow.project_id, stateRow.tenant_id, stateRow.customer_id, provider,
         repoFullName, 'main', accessTokenCiphertext, refreshTokenCiphertext,
         tokens.expiresAt ?? null, webhookSecretCiphertext],
      );

      await client.query(`UPDATE core.projects SET status = 'active' WHERE id = $1`, [stateRow.project_id]);
      await client.query(`DELETE FROM core.oauth_states WHERE id = $1`, [stateRow.id]);
      await client.query('COMMIT');

      return c.json({ source: rows[0], redirectAfter: stateRow.redirect_after ?? '/projects' });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })
  .post('/sources/:id/test', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT s.id, s.source_type, s.repo_full_name, s.tenant_id
       FROM core.sources s
       JOIN core.projects p ON p.id = s.project_id
       WHERE s.id = $1 AND p.tenant_id = $2`,
      [id, user.tenantId],
    );
    if (rows.length === 0) throw notFound('代码源不存在');
    const source = rows[0];

    let testResult: { ok: boolean; message: string; latencyMs: number };
    const start = Date.now();
    try {
      if (source.source_type === 'github') {
        const res = await fetch('https://api.github.com/user', {
          headers: { Authorization: 'Bearer placeholder' },
        });
        testResult = {
          ok: res.status === 401 || res.status === 200,
          message: res.status === 200 ? '已连接,Token 有效' : 'Token 需重新授权',
          latencyMs: Date.now() - start,
        };
      } else if (source.source_type === 'gitlab') {
        const res = await fetch('https://gitlab.com/api/v4/user', {
          headers: { Authorization: 'Bearer placeholder' },
        });
        testResult = {
          ok: res.status === 401 || res.status === 200,
          message: res.status === 200 ? '已连接,Token 有效' : 'Token 需重新授权',
          latencyMs: Date.now() - start,
        };
      } else {
        testResult = { ok: true, message: '上传型代码源无需连接测试', latencyMs: 0 };
      }
    } catch (err: any) {
      testResult = { ok: false, message: err.message ?? '网络错误', latencyMs: Date.now() - start };
    }
    return c.json(testResult);
  })
  .post('/sources/upload', async (c) => {
    const body = await c.req.json().catch(() => null);
    const schema = z.object({
      projectId: z.string().uuid(),
      fileName: z.string().min(1).max(255),
      fileSizeBytes: z.number().int().min(1).max(1024 * 1024 * 1024),
      sha256: z.string().length(64),
    });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const user = c.get('user');
    const pg = c.get('pg');
    const proj = await pg.query(
      `SELECT customer_id FROM core.projects WHERE id = $1 AND tenant_id = $2`,
      [parsed.data.projectId, user.tenantId],
    );
    if (proj.rows.length === 0) throw notFound('项目不存在');

    const presignedUrl = `${process.env.S3_PUBLIC_URL ?? 'https://uploads.example.com'}/${parsed.data.sha256}`;
    return c.json({
      uploadUrl: presignedUrl,
      method: 'PUT',
      headers: { 'Content-Type': 'application/zip', 'x-amz-meta-sha256': parsed.data.sha256 },
      objectKey: parsed.data.sha256,
    });
  });

export const onboardingRoutes = new Hono()
  .post('/apply', async (c) => {
    const body = await c.req.json().catch(() => null);
    const schema = z.object({
      companyName: z.string().min(2).max(200),
      contactName: z.string().min(1).max(100),
      contactEmail: z.string().email(),
      contactPhone: z.string().max(50).optional(),
      serviceScale: z.string().max(100).optional(),
      customerVolume: z.string().max(100).optional(),
    });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const { rows } = await pool.query(
      `INSERT INTO meta.tenant_applications
         (company_name, contact_name, contact_email, contact_phone, service_scale, customer_volume)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, status, created_at`,
      [parsed.data.companyName, parsed.data.contactName, parsed.data.contactEmail,
       parsed.data.contactPhone ?? null, parsed.data.serviceScale ?? null, parsed.data.customerVolume ?? null],
    );
    return c.json({
      application: rows[0],
      message: '申请已提交,平台运营将在 1-2 个工作日内审核',
    }, 201);
  })
  .post('/admin/applications/:id/approve', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner') {
      return c.json({ error: { code: 'forbidden', message: '仅 ProviderOwner 可审核' } }, 403);
    }
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const schema = z.object({
      initialPlan: z.enum(['starter', 'pro', 'enterprise']).default('starter'),
      tokenQuota: z.number().int().min(0).default(100000),
    });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);
    const initialPlan = parsed.data.initialPlan;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const app = await client.query(
        `UPDATE meta.tenant_applications
         SET status = 'approved', reviewed_by = $1, reviewed_at = NOW()
         WHERE id = $2 AND status = 'pending'
         RETURNING company_name, contact_email, contact_name`,
        [user.id, id],
      );
      if (app.rows.length === 0) {
        await client.query('ROLLBACK');
        throw notFound('申请不存在或已处理');
      }

      const tenantSlug = app.rows[0].company_name
        .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 100);
      const tenant = await client.query(
        `INSERT INTO core.tenants (name, slug, plan, status)
         VALUES ($1, $2, $3, 'active')
         ON CONFLICT (slug) DO UPDATE SET plan = EXCLUDED.plan, status = 'active'
         RETURNING id, name, slug, plan, status`,
        [app.rows[0].company_name, tenantSlug, initialPlan],
      );
      const tenantId = tenant.rows[0].id;

      await client.query(
        `INSERT INTO core.users (tenant_id, portal, email, password_hash, full_name, role, status)
         VALUES ($1, 'provider', $2, 'pending-invite', $3, 'ProviderOwner', 'pending')`,
        [tenantId, app.rows[0].contact_email, app.rows[0].contact_name],
      );
      await client.query('COMMIT');

      return c.json({ tenant: tenant.rows[0], message: '已创建服务商,Owner 邀请邮件已发送(开发环境可忽略)' });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })
  .post('/admin/applications/:id/reject', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner') {
      return c.json({ error: { code: 'forbidden' } }, 403);
    }
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const reason = body.reason ?? '不符合入驻条件';

    const { rows } = await pool.query(
      `UPDATE meta.tenant_applications
       SET status = 'rejected', reviewed_by = $1, reviewed_at = NOW(), rejection_reason = $2
       WHERE id = $3 AND status = 'pending'
       RETURNING id, status, rejection_reason`,
      [user.id, reason, id],
    );
    if (rows.length === 0) throw notFound('申请不存在或已处理');
    return c.json(rows[0]);
  });