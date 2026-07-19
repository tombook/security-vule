import { Hono } from 'hono';
import { z } from 'zod';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { pool } from '../db/client';
import { notFound } from '../middleware/error';

const configSchema = z.object({
  customerId: z.string().uuid(),
  system: z.enum(['jira', 'github_issues', 'gitlab_issues', 'webhook', 'linear', 'zentao', 'redmine', 'custom']),
  displayName: z.string().min(1).max(100),
  apiBaseUrl: z.string().url().optional(),
  projectKey: z.string().max(50).optional(),
  repoFullName: z.string().max(200).optional(),
  defaultAssignees: z.array(z.string()).default([]),
  defaultLabels: z.array(z.string()).default([]),
  eventMapping: z.record(z.string(), z.array(z.string())).default({}),
  enabled: z.boolean().default(true),
});

function encryptToken(plaintext: string): Buffer {
  const key = createHash('sha256').update(process.env.SOURCE_TOKEN_KMS_KEY ?? process.env.JWT_SECRET ?? 'dev').digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, enc, tag]);
}

async function pushToJira(integration: any, finding: any, token: string): Promise<{ externalRef: string; httpStatus: number; responseBody: string }> {
  const url = `${integration.api_base_url}/rest/api/3/issue`;
  const body = {
    fields: {
      project: { key: integration.project_key },
      summary: `[${finding.severity.toUpperCase()}] ${finding.title}`,
      description: {
        type: 'doc',
        version: 1,
        content: [{ type: 'paragraph', content: [{ type: 'text', text: finding.description ?? finding.title }] }],
      },
      labels: [...(integration.default_labels ?? []), 'security-vule', finding.severity],
    },
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  return { externalRef: data.key ?? '', httpStatus: res.status, responseBody: text };
}

async function pushToGithub(integration: any, finding: any, token: string): Promise<{ externalRef: string; httpStatus: number; responseBody: string }> {
  const [owner, repo] = (integration.repo_full_name ?? '').split('/');
  if (!owner || !repo) throw new Error('repo_full_name 配置错误');
  const url = `https://api.github.com/repos/${owner}/${repo}/issues`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      title: `[${finding.severity.toUpperCase()}] ${finding.title}`,
      body: `${finding.description ?? finding.title}\n\nFile: ${finding.file_path}:${finding.start_line}\nSeverity: ${finding.severity}`,
      labels: [...(integration.default_labels ?? []), 'security', finding.severity],
    }),
  });
  const data = await res.json();
  return { externalRef: String(data.number ?? ''), httpStatus: res.status, responseBody: JSON.stringify(data) };
}

async function pushToGitlab(integration: any, finding: any, token: string): Promise<{ externalRef: string; httpStatus: number; responseBody: string }> {
  const url = `${integration.api_base_url ?? 'https://gitlab.com'}/api/v4/projects/${encodeURIComponent(integration.project_key ?? '')}/issues`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'PRIVATE-TOKEN': token },
    body: JSON.stringify({
      title: `[${finding.severity.toUpperCase()}] ${finding.title}`,
      description: `${finding.description ?? finding.title}\n\nFile: ${finding.file_path}:${finding.start_line}`,
      labels: (integration.default_labels ?? []).join(',') + `,security,${finding.severity}`,
    }),
  });
  const data = await res.json();
  return { externalRef: String(data.iid ?? ''), httpStatus: res.status, responseBody: JSON.stringify(data) };
}

async function pushToWebhook(integration: any, finding: any): Promise<{ externalRef: string; httpStatus: number; responseBody: string }> {
  const res = await fetch(integration.api_base_url ?? '', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Security-Vule-Signature': 'mock-hmac' },
    body: JSON.stringify({
      event: 'finding.escalated',
      finding: {
        id: finding.id, title: finding.title, severity: finding.severity, status: finding.status,
        file_path: finding.file_path, start_line: finding.start_line,
        cwe_ids: finding.cwe_ids, owasp_ids: finding.owasp_ids,
      },
    }),
  });
  return { externalRef: '', httpStatus: res.status, responseBody: await res.text() };
}

export const ticketIntegrationsRoutes = new Hono()
  .get('/', async (c) => {
    const user = c.get('user');
    const customerId = c.req.query('customerId');
    const params: unknown[] = [user.tenantId];
    let where = 'tenant_id = $1';
    if (customerId) { params.push(customerId); where += ` AND customer_id = $${params.length}`; }
    const { rows } = await pool.query(
      `SELECT id, customer_id, system, display_name, project_key, repo_full_name,
              enabled, last_sync_at, last_sync_status, last_sync_error, created_at
       FROM integration.ticket_integrations
       WHERE ${where}
       ORDER BY created_at DESC`,
      params,
    );
    return c.json({ items: rows });
  })
  .post('/', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner' && user.role !== 'ProviderAdmin') {
      return c.json({ error: { code: 'forbidden' } }, 403);
    }
    const body = await c.req.json().catch(() => ({}));
    const parsed = configSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const encryptedToken = parsed.data.system !== 'webhook' && parsed.data.apiBaseUrl
      ? encryptToken(process.env.TEST_TICKET_TOKEN ?? 'placeholder-token')
      : null;

    const { rows } = await pool.query(
      `INSERT INTO integration.ticket_integrations
         (tenant_id, customer_id, system, display_name, api_base_url, project_key,
          repo_full_name, api_token_ciphertext, default_assignees, default_labels,
          event_mapping, enabled, created_by)
       VALUES ($1, $2, $3::ticket_system_enum, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING id, customer_id, system, display_name, enabled, created_at`,
      [
        user.tenantId, parsed.data.customerId ?? null, parsed.data.system, parsed.data.displayName,
        parsed.data.apiBaseUrl ?? null, parsed.data.projectKey ?? null, parsed.data.repoFullName ?? null,
        encryptedToken, parsed.data.defaultAssignees, parsed.data.defaultLabels,
        JSON.stringify(parsed.data.eventMapping), parsed.data.enabled, user.id,
      ],
    );
    return c.json(rows[0], 201);
  })
  .patch('/:id', async (c) => {
    const user = c.get('user');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const schema = configSchema.partial();
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const sets: string[] = [];
    const params: unknown[] = [];
    for (const [k, v] of Object.entries(parsed.data)) {
      if (v === undefined) continue;
      const col = k.replace(/[A-Z]/g, (m) => `_${m.toLowerCase()}`);
      params.push(col === 'system' ? `${v}::ticket_system_enum` : JSON.stringify(v));
      sets.push(`${col} = $${params.length}`);
    }
    if (!sets.length) return c.json({ error: { code: 'bad_request', message: '无字段更新' } }, 400);
    sets.push('updated_at = NOW()');
    params.push(id, user.tenantId);
    const { rows } = await pool.query(
      `UPDATE integration.ticket_integrations SET ${sets.join(', ')}
       WHERE id = $${params.length - 1} AND tenant_id = $${params.length}
       RETURNING id, display_name, enabled, updated_at`,
      params,
    );
    if (!rows.length) throw notFound('集成不存在');
    return c.json(rows[0]);
  })
  .delete('/:id', async (c) => {
    const user = c.get('user');
    const id = c.req.param('id');
    const { rows } = await pool.query(
      `UPDATE integration.ticket_integrations
       SET enabled = false, deleted_at = NOW()
       WHERE id = $1 AND tenant_id = $2
       RETURNING id, enabled`,
      [id, user.tenantId],
    );
    if (!rows.length) throw notFound('集成不存在');
    return c.json({ disabled: rows[0] });
  })
  .post('/:id/test', async (c) => {
    const user = c.get('user');
    const id = c.req.param('id');
    const { rows } = await pool.query(
      `SELECT system, api_base_url, project_key, repo_full_name
       FROM integration.ticket_integrations
       WHERE id = $1 AND tenant_id = $2`,
      [id, user.tenantId],
    );
    if (!rows.length) throw notFound('集成不存在');
    const integration = rows[0];
    const start = Date.now();
    try {
      if (integration.system === 'webhook') {
        const res = await fetch(integration.api_base_url ?? '', { method: 'HEAD' });
        return c.json({ ok: res.status < 500, message: `HTTP ${res.status}`, latencyMs: Date.now() - start });
      }
      return c.json({ ok: true, message: '配置已就绪(需真实 token 才能推送)', latencyMs: Date.now() - start });
    } catch (err: any) {
      return c.json({ ok: false, message: err.message, latencyMs: Date.now() - start });
    }
  })
  .post('/push/:findingId', async (c) => {
    const user = c.get('user');
    const findingId = c.req.param('findingId');
    const body = await c.req.json().catch(() => ({}));
    const integrationId = body.integration_id;

    const { rows: finding } = await pool.query(
      `SELECT id, customer_id, severity, status, title, description, file_path, start_line, cwe_ids, owasp_ids
       FROM detection.findings WHERE id = $1 AND tenant_id = $2`,
      [findingId, user.tenantId],
    );
    if (!finding.length) throw notFound('漏洞不存在');
    const f = finding[0];

    const { rows: integrations } = await pool.query(
      `SELECT id, system, api_base_url, project_key, repo_full_name, default_labels
       FROM integration.ticket_integrations
       WHERE id = $1 AND tenant_id = $2 AND enabled = true AND deleted_at IS NULL`,
      [integrationId, user.tenantId],
    );
    if (!integrations.length) throw notFound('集成不存在或已禁用');
    const integration = integrations[0];

    const token = process.env.TEST_TICKET_TOKEN ?? 'placeholder-token';
    const start = Date.now();
    let result: { externalRef: string; httpStatus: number; responseBody: string };
    try {
      switch (integration.system) {
        case 'jira': result = await pushToJira(integration, f, token); break;
        case 'github_issues': result = await pushToGithub(integration, f, token); break;
        case 'gitlab_issues': result = await pushToGitlab(integration, f, token); break;
        case 'webhook': result = await pushToWebhook(integration, f); break;
        default: return c.json({ error: { code: 'unsupported' } }, 400);
      }
    } catch (err: any) {
      await pool.query(
        `INSERT INTO integration.ticket_sync_log
           (tenant_id, customer_id, integration_id, finding_id, direction, status, error_message, duration_ms)
         VALUES ($1, $2, $3, $4, 'outbound_only', 'failed', $5, $6)`,
        [user.tenantId, f.customer_id, integrationId, findingId, err.message, Date.now() - start],
      );
      return c.json({ pushed: false, error: err.message });
    }

    await pool.query(
      `INSERT INTO integration.ticket_sync_log
         (tenant_id, customer_id, integration_id, finding_id, external_ref, direction, status,
          http_status, response_body, duration_ms)
       VALUES ($1, $2, $3, $4, $5, 'outbound_only', $6, $7, $8, $9)`,
      [
        user.tenantId, f.customer_id, integrationId, findingId, result.externalRef,
        result.httpStatus < 400 ? 'success' : 'failed',
        result.httpStatus, result.responseBody.slice(0, 1000), Date.now() - start,
      ],
    );
    await pool.query(
      `UPDATE integration.ticket_integrations
       SET last_sync_at = NOW(), last_sync_status = $1, last_sync_error = $2
       WHERE id = $3`,
      [result.httpStatus < 400 ? 'success' : 'failed', result.httpStatus < 400 ? null : result.responseBody.slice(0, 500), integrationId],
    );

    return c.json({
      pushed: result.httpStatus < 400,
      externalRef: result.externalRef,
      httpStatus: result.httpStatus,
      durationMs: Date.now() - start,
    });
  })
  .get('/sync-log', async (c) => {
    const user = c.get('user');
    const findingId = c.req.query('findingId');
    const params: unknown[] = [user.tenantId];
    let where = 'tenant_id = $1';
    if (findingId) { params.push(findingId); where += ` AND finding_id = $${params.length}`; }
    const { rows } = await pool.query(
      `SELECT id, integration_id, finding_id, external_ref, direction, status,
              http_status, duration_ms, error_message, created_at
       FROM integration.ticket_sync_log
       WHERE ${where}
       ORDER BY created_at DESC
       LIMIT 100`,
      params,
    );
    return c.json({ items: rows });
  });