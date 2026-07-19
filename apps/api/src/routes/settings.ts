import { Hono } from 'hono';
import { pool } from '../db/client';
import { requireRole, PROVIDER_ADMIN_ROLES } from '../middleware/rbac';
import { createClientFromConfig } from '../services/llm/client';

interface LLMProviderConfig {
  id: string;
  provider: 'openai' | 'anthropic' | 'ollama' | 'glm' | 'deepseek' | 'custom';
  name: string;
  enabled: boolean;
  priority: number;
  apiKey?: string;
  baseUrl?: string;
  defaultModel: string;
  modelOptions: string[];
  inputPricePerMTok: number;
  outputPricePerMTok: number;
  createdAt: string;
  updatedAt: string;
}

const DEFAULT_PROVIDERS: Omit<LLMProviderConfig, 'createdAt' | 'updatedAt'>[] = [
  { id: 'ollama-default', provider: 'ollama', name: 'Ollama (Local)', enabled: true, priority: 1, baseUrl: 'http://localhost:11434', defaultModel: 'security-vule-poc-v1', modelOptions: ['security-vule-poc-v1', 'llama3.1'], inputPricePerMTok: 0, outputPricePerMTok: 0 },
  { id: 'openai-default', provider: 'openai', name: 'OpenAI', enabled: false, priority: 2, defaultModel: 'gpt-4o-mini', modelOptions: ['gpt-4o-mini', 'gpt-4o', 'gpt-4'], inputPricePerMTok: 0.15, outputPricePerMTok: 0.6 },
  { id: 'anthropic-default', provider: 'anthropic', name: 'Anthropic', enabled: false, priority: 3, defaultModel: 'claude-sonnet-4-5', modelOptions: ['claude-sonnet-4-5', 'claude-opus-4'], inputPricePerMTok: 3, outputPricePerMTok: 15 },
  { id: 'glm-default', provider: 'glm', name: '智谱 GLM', enabled: false, priority: 4, baseUrl: 'https://open.bigmodel.cn/api/paas/v4', defaultModel: 'glm-4-flash', modelOptions: ['glm-4-flash', 'glm-4', 'glm-5.2'], inputPricePerMTok: 0, outputPricePerMTok: 0 },
  { id: 'deepseek-default', provider: 'deepseek', name: 'DeepSeek', enabled: false, priority: 5, baseUrl: 'https://api.deepseek.com', defaultModel: 'deepseek-chat', modelOptions: ['deepseek-chat'], inputPricePerMTok: 0.14, outputPricePerMTok: 0.28 },
];

function mapRow(r: any) {
  return {
    id: r.id, provider: r.provider, name: r.name, enabled: r.enabled, priority: r.priority,
    apiKey: r.api_key ? `${r.api_key.slice(0, 6)}...` : null,
    baseUrl: r.base_url, defaultModel: r.default_model, modelOptions: r.model_options,
    inputPricePerMTok: Number(r.input_price_per_m_tok ?? 0),
    outputPricePerMTok: Number(r.output_price_per_m_tok ?? 0),
    createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

export const settingsRoutes = new Hono()
  .get('/organization', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, name, slug, plan, status, white_label, application_payload, created_at
       FROM core.tenants
       WHERE id = $1`,
      [c.get('user').tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found', message: 'tenant not found' } }, 404);
    const r = rows[0];
    return c.json({
      id: r.id, name: r.name, slug: r.slug, plan: r.plan, status: r.status,
      whiteLabel: r.white_label, applicationPayload: r.application_payload, createdAt: r.created_at,
    });
  })
  .put('/organization', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const body = await c.req.json().catch(() => null) as { name?: string } | null;
    if (!body?.name) return c.json({ error: { code: 'bad_request', message: 'name required' } }, 400);
    const pg = c.get('pg');
    const user = c.get('user') as any;
    await pg.query(`UPDATE core.tenants SET name = $1 WHERE id = $2`, [body.name, user.tenantId]);
    return c.json({ ok: true });
  })
  .get('/api-keys', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, name, key_prefix, scopes, last_used_at, last_used_ip, expires_at,
              created_by, created_at, revoked_at
       FROM core.api_keys
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [c.get('user').tenantId],
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, name: r.name, keyPrefix: r.key_prefix, scopes: r.scopes,
        lastUsedAt: r.last_used_at, lastUsedIp: r.last_used_ip, expiresAt: r.expires_at,
        createdBy: r.created_by, createdAt: r.created_at, revokedAt: r.revoked_at,
        isActive: !r.revoked_at,
      })),
    });
  })
  .post('/api-keys', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const body = await c.req.json().catch(() => null) as { name?: string; scopes?: string[]; expires_in_days?: number; projectId?: string; customerId?: string } | null;
    if (!body?.name) return c.json({ error: { code: 'bad_request', message: 'name required' } }, 400);

    const keyBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(crypto.randomUUID() + Date.now()));
    const keyHex = Array.from(new Uint8Array(keyBytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
    const keyPrefix = 'sv_live_' + keyHex.slice(0, 8);

    const pg = c.get('pg');
    const user = c.get('user') as any;
    const expiresAt = body.expires_in_days ? new Date(Date.now() + body.expires_in_days * 86400000) : null;

    let customerId = body.customerId ?? null;
    let projectId = body.projectId ?? null;
    if (projectId && !customerId) {
      const { rows: proj } = await pg.query(`SELECT customer_id FROM core.projects WHERE id = $1 AND tenant_id = $2`, [projectId, user.tenantId]);
      if (proj.length > 0) customerId = proj[0].customer_id;
    }
    if (!customerId) {
      const { rows: cust } = await pg.query(`SELECT id FROM core.customers WHERE tenant_id = $1 LIMIT 1`, [user.tenantId]);
      if (cust.length > 0) customerId = cust[0].id;
    }
    if (!projectId) {
      const { rows: proj } = await pg.query(`SELECT id FROM core.projects WHERE tenant_id = $1 AND customer_id = $2 LIMIT 1`, [user.tenantId, customerId]);
      if (proj.length > 0) projectId = proj[0].id;
    }

    const { rows } = await pg.query(
      `INSERT INTO core.api_keys
         (tenant_id, customer_id, project_id, name, key_prefix, key_hash, scopes, expires_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, name, key_prefix, scopes, expires_at, created_at`,
      [
        user.tenantId, customerId, projectId, body.name, keyPrefix, keyHex, body.scopes ?? [],
        expiresAt, user.id,
      ],
    );
    return c.json({ ...rows[0], keyPlain: 'sv_live_' + keyHex.slice(0, 32) }, 201);
  })
  .delete('/api-keys/:id', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const { rows } = await pg.query(
      `UPDATE core.api_keys
       SET revoked_at = NOW(), revoked_by = $1
       WHERE id = $2 AND tenant_id = $3 AND revoked_at IS NULL
       RETURNING id`,
      [c.get('user').id, id, c.get('user').tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found', message: 'key not found or already revoked' } }, 404);
    return c.json(rows[0]);
  })
  .get('/notifications', async (c) => {
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, email, full_name, role, notification_prefs
       FROM core.users
       WHERE id = $1`,
      [c.get('user').id],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found' } }, 404);
    return c.json(rows[0].notification_prefs);
  })
  .put('/notifications', async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ error: { code: 'bad_request', message: 'body required' } }, 400);
    const pg = c.get('pg');
    await pg.query(
      `UPDATE core.users SET notification_prefs = $1 WHERE id = $2`,
      [JSON.stringify(body), c.get('user').id],
    );
    return c.json({ ok: true });
  })
  // ── LLM Providers: GET ───────────────────────────────────────
  .get('/llm-providers', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const user = c.get('user') as any;
    const { rows } = await (c.get('pg') as any).query(
      `SELECT id, provider, name, enabled, priority, api_key, base_url, default_model, model_options,
              input_price_per_m_tok, output_price_per_m_tok, created_at, updated_at
       FROM core.llm_provider_configs
       WHERE tenant_id = $1
       ORDER BY priority ASC`,
      [user.tenantId],
    );
    if (rows.length > 0) {
      return c.json({ items: rows.map(mapRow) });
    }
    const now = new Date().toISOString();
    return c.json({ items: DEFAULT_PROVIDERS.map((p) => ({ ...p, createdAt: now, updatedAt: now })) });
  })
  // ── LLM Providers: PUT (upsert all) ─────────────────────────
  .put('/llm-providers', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const body = await c.req.json().catch(() => null) as any[];
    if (!Array.isArray(body)) return c.json({ error: { code: 'bad_request', message: 'array expected' } }, 400);
    const pg = c.get('pg') as any;
    const user = c.get('user') as any;

    // Delete providers that are no longer in the payload
    const incomingIds = body.map((p) => p.id);
    await pg.query(
      `DELETE FROM core.llm_provider_configs WHERE tenant_id = $1 AND NOT (id = ANY($2::text[]))`,
      [user.tenantId, incomingIds],
    );

    for (const p of body) {
      await pg.query(
        `INSERT INTO core.llm_provider_configs
           (id, tenant_id, provider, name, enabled, priority, api_key, base_url, default_model, model_options,
            input_price_per_m_tok, output_price_per_m_tok)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (id) DO UPDATE
           SET name = EXCLUDED.name, enabled = EXCLUDED.enabled, priority = EXCLUDED.priority,
               api_key = CASE
                 WHEN EXCLUDED.api_key IS NULL OR EXCLUDED.api_key = '' OR EXCLUDED.api_key LIKE '%...'
                   THEN core.llm_provider_configs.api_key
                 ELSE EXCLUDED.api_key
               END,
               base_url = EXCLUDED.base_url,
               default_model = EXCLUDED.default_model, model_options = EXCLUDED.model_options,
               input_price_per_m_tok = EXCLUDED.input_price_per_m_tok,
               output_price_per_m_tok = EXCLUDED.output_price_per_m_tok,
               updated_at = NOW()
        RETURNING id`,
        [
          p.id, user.tenantId, p.provider, p.name, p.enabled, p.priority,
          p.apiKey || null, p.baseUrl || null, p.defaultModel, JSON.stringify(p.modelOptions ?? []),
          p.inputPricePerMTok ?? 0, p.outputPricePerMTok ?? 0,
        ],
      );
    }
    const { rows } = await pg.query(
      `SELECT id, provider, name, enabled, priority, api_key, base_url, default_model, model_options,
              input_price_per_m_tok, output_price_per_m_tok, created_at, updated_at
       FROM core.llm_provider_configs
       WHERE tenant_id = $1
       ORDER BY priority ASC`,
      [user.tenantId],
    );
    return c.json({ items: rows.map(mapRow) });
  })
  // ── LLM Providers: DELETE single ────────────────────────────
  .delete('/llm-providers/:id', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const id = c.req.param('id');
    const pg = c.get('pg') as any;
    const user = c.get('user') as any;
    await pg.query(`DELETE FROM core.llm_provider_configs WHERE id = $1 AND tenant_id = $2`, [id, user.tenantId]);
    return c.json({ ok: true });
  })
  // ── LLM Providers: test connection ──────────────────────────
  .post('/llm-providers/test', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const body = await c.req.json().catch(() => null) as {
      id?: string; provider: string; apiKey?: string; baseUrl?: string; defaultModel: string;
    } | null;
    if (!body?.provider) return c.json({ error: { code: 'bad_request', message: 'provider required' } }, 400);

    const pg = c.get('pg') as any;
    const user = c.get('user') as any;

    // If apiKey is masked or empty, look up the real key from DB
    let apiKey = body.apiKey;
    if ((!apiKey || apiKey.endsWith('...')) && body.id) {
      const { rows } = await pg.query(
        `SELECT api_key FROM core.llm_provider_configs WHERE id = $1 AND tenant_id = $2`,
        [body.id, user.tenantId],
      );
      if (rows.length > 0) apiKey = rows[0].api_key;
    }

    try {
      // For ollama, check /api/tags instead of a full chat
      if (body.provider === 'ollama') {
        const base = body.baseUrl || 'http://localhost:11434';
        const start = Date.now();
        const res = await fetch(`${base}/api/tags`, { signal: AbortSignal.timeout(5000) });
        if (!res.ok) {
          return c.json({ ok: false, error: `HTTP ${res.status}` });
        }
        const data: any = await res.json();
        const modelCount = data.models?.length ?? 0;
        return c.json({ ok: true, model: body.defaultModel, latencyMs: Date.now() - start, detail: `Ollama 在线, ${modelCount} 个模型可用` });
      }

      // For other providers, send a minimal chat: "Hi" with max_tokens=5
      const client = createClientFromConfig({
        provider: body.provider as any,
        defaultModel: body.defaultModel,
        apiKey: apiKey || undefined,
        baseUrl: body.baseUrl,
      });
      const start = Date.now();
      const resp = await client.chat({
        messages: [{ role: 'user', content: 'Hi' }],
        maxTokens: 5,
        temperature: 0,
      });
      return c.json({
        ok: true,
        model: resp.model,
        latencyMs: Date.now() - start,
        detail: `响应 ${resp.totalTokens} tokens, 费用 $${resp.costUsd.toFixed(6)}`,
      });
    } catch (err: any) {
      return c.json({ ok: false, error: err.message ?? String(err) });
    }
  });
