import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';
import { notFound } from '../middleware/error';
import { requireRole, PROVIDER_WRITE_ROLES } from '../middleware/rbac';

const listSchema = z.object({
  customerId: z.string().uuid().optional(),
  projectId: z.string().uuid().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  status: z.enum(['open', 'in_progress', 'fixed', 'regressed', 'false_positive', 'accepted_risk', 'escalated', 'confirmed']).optional(),
  ruleId: z.string().uuid().optional(),
  q: z.string().optional(),
  page: z.coerce.number().int().min(1).default(1),
  size: z.coerce.number().int().min(1).max(100).default(20),
});

const patchSchema = z.object({
  status: z.enum(['open', 'in_progress', 'fixed', 'false_positive', 'accepted_risk', 'escalated']).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  reason: z.string().max(500).optional(),
});

const bulkSchema = z.object({
  ids: z.array(z.string().uuid()).min(1).max(100),
  action: z.enum(['triage', 'escalate', 'false_positive', 'accepted_risk']),
  reason: z.string().max(500).optional(),
});

const commentSchema = z.object({
  type: z.enum(['note', 'triage', 'fix_commit', 'external_link', 'system']).default('note'),
  body: z.string().min(1).max(2000),
  mention_user_ids: z.array(z.string().uuid()).optional(),
});

function severityColor(s: string) {
  return s === 'critical' ? 'danger' : s === 'high' ? 'warning' : s === 'medium' ? '' : 'info';
}

export const findingsRoutes = new Hono()
  .get('/', async (c) => {
    const url = new URL(c.req.url);
    const raw = Object.fromEntries(url.searchParams.entries());
    const parsed = listSchema.safeParse(raw);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'Invalid query' } }, 400);

    const { customerId, projectId, severity, status, ruleId, q, page, size } = parsed.data;
    const user = c.get('user');
    const offset = (page - 1) * size;

    const whereItems: string[] = ['f.tenant_id = $1'];
    const whereCount: string[] = ['tenant_id = $1'];
    const params: unknown[] = [user.tenantId];
    const addParam = (val: unknown) => { params.push(val); return params.length; };
    if (customerId) { const p = addParam(customerId); whereItems.push(`f.customer_id = $${p}`); whereCount.push(`customer_id = $${p}`); }
    if (projectId) { const p = addParam(projectId); whereItems.push(`f.project_id = $${p}`); whereCount.push(`project_id = $${p}`); }
    if (severity) { const p = addParam(severity); whereItems.push(`f.severity = $${p}::severity_enum`); whereCount.push(`severity = $${p}::severity_enum`); }
    if (status) { const p = addParam(status); whereItems.push(`f.status = $${p}::finding_status_enum`); whereCount.push(`status = $${p}::finding_status_enum`); }
    if (ruleId) { const p = addParam(ruleId); whereItems.push(`f.rule_id = $${p}`); whereCount.push(`rule_id = $${p}`); }
    if (q) { const p = addParam(`%${q}%`); whereItems.push(`(f.title ILIKE $${p} OR f.file_path ILIKE $${p})`); whereCount.push(`(title ILIKE $${p} OR file_path ILIKE $${p})`); }

    const whereItemsClause = `WHERE ${whereItems.join(' AND ')}`;
    const whereCountClause = `WHERE ${whereCount.join(' AND ')}`;
    const baseParamCount = params.length;
    params.push(size, offset);

    const itemsRes = await pool.query(
      `SELECT f.id, f.customer_id, c.name AS customer_name, f.project_id, p.name AS project_name,
              f.severity, f.status, f.title, f.file_path, f.start_line, f.end_line,
              f.cwe_ids, f.owasp_ids, f.first_seen_at, f.last_seen_at, f.created_at,
              (SELECT count(*) FROM poc.poc_runs pr WHERE pr.finding_id = f.id) AS poc_run_count
       FROM detection.findings f
       JOIN core.customers c ON c.id = f.customer_id
       JOIN core.projects p ON p.id = f.project_id
       ${whereItemsClause}
       ORDER BY
         CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
         f.last_seen_at DESC NULLS LAST
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );

    const countRes = await pool.query(
      `SELECT count(*)::int AS total FROM detection.findings ${whereCountClause}`,
      params.slice(0, baseParamCount),
    );

    return c.json({
      items: itemsRes.rows,
      total: countRes.rows[0]?.total ?? 0,
      page,
      size,
    });
  })
  .get('/severity-breakdown', async (c) => {
    const user = c.get('user');
    const { rows } = await pool.query(
      `SELECT severity, status, count(*)::int AS count
       FROM detection.findings
       WHERE tenant_id = $1
       GROUP BY severity, status
       ORDER BY severity, status`,
      [user.tenantId],
    );
    return c.json({ breakdown: rows });
  })

  // ── Summary: findings grouped by (customer, project) ─────────
  // Used by /findings (no ?project= query) — the default landing
  // view should be a roll-up table, not the 1000+ row detail list.
  // Each row aggregates open / closed / total counts and the
  // severity breakdown for one project under one customer.
  .get('/summary', async (c) => {
    const user = c.get('user');
    const customerId = c.req.query('customerId');
    const params: unknown[] = [user.tenantId];
    const where: string[] = ['f.tenant_id = $1'];
    if (customerId) {
      params.push(customerId);
      where.push(`f.customer_id = $${params.length}`);
    }
    const { rows } = await pool.query(
      `SELECT
          f.customer_id,
          c.name         AS customer_name,
          f.project_id,
          p.name         AS project_name,
          p.status       AS project_status,
          count(*)::int                            AS total,
          count(*) FILTER (WHERE f.status='open')::int   AS open_count,
          count(*) FILTER (WHERE f.status='closed' OR f.status='fixed' OR f.status='false_positive')::int AS closed_count,
          count(*) FILTER (WHERE f.severity='critical')::int AS critical,
          count(*) FILTER (WHERE f.severity='high')::int     AS high,
          count(*) FILTER (WHERE f.severity='medium')::int   AS medium,
          count(*) FILTER (WHERE f.severity='low')::int      AS low,
          max(f.created_at)                          AS last_finding_at,
          coalesce(poc.cnt, 0)::int                  AS poc_total,
          coalesce(poc.proven_cnt, 0)::int           AS poc_proven
       FROM detection.findings f
       JOIN core.customers c ON c.id = f.customer_id
       JOIN core.projects  p ON p.id = f.project_id
       LEFT JOIN LATERAL (
         SELECT count(*) AS cnt,
                count(*) FILTER (WHERE pr.exploit_proven = true) AS proven_cnt
         FROM poc.poc_runs pr
         JOIN detection.findings df
           ON df.id = pr.finding_id
          AND df.tenant_id = f.tenant_id
          AND df.customer_id = f.customer_id
          AND df.project_id = f.project_id
       ) poc ON true
       WHERE ${where.join(' AND ')}
       GROUP BY f.customer_id, c.name, f.project_id, p.name, p.status,
                poc.cnt, poc.proven_cnt
       ORDER BY total DESC, critical DESC, high DESC`,
      params,
    );
    return c.json({ items: rows });
  })
  .get('/:id', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const { rows } = await pool.query(
      `SELECT f.*, c.name AS customer_name, p.name AS project_name,
              r.title AS rule_title, r.severity AS rule_severity, r.cwe_ids AS rule_cwe_ids
       FROM detection.findings f
       JOIN core.customers c ON c.id = f.customer_id
       JOIN core.projects p ON p.id = f.project_id
       JOIN detection.rules r ON r.id = f.rule_id
       WHERE f.id = $1 AND f.tenant_id = $2`,
      [id, user.tenantId],
    );
    if (rows.length === 0) throw notFound('漏洞不存在');
    const finding = rows[0];

    const [historyRes, commentsRes, pocRes] = await Promise.all([
      pool.query(
        `SELECT id, from_status, to_status, change_source, changed_by, occurred_at, reason
         FROM detection.finding_state_history
         WHERE finding_id = $1 ORDER BY occurred_at DESC LIMIT 50`,
        [id]),
      pool.query(
        `SELECT id, comment_type, body, author_user_id, created_at
         FROM detection.finding_comments
         WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 50`,
        [id]),
      pool.query(
        `SELECT id, status, exploit_proven, created_at
         FROM poc.poc_runs
         WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 10`,
        [id]),
    ]);

    return c.json({
      ...finding,
      stateHistory: historyRes.rows,
      comments: commentsRes.rows,
      pocRuns: pocRes.rows,
    });
  })
  .patch('/:id', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const body = await c.req.json().catch(() => ({}));
    const parsed = patchSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL app.current_tenant = '${user.tenantId}'`);
      await client.query(`SET LOCAL app.current_user_role = '${user.role}'`);

      const current = await client.query(
        `SELECT id, status, severity FROM detection.findings WHERE id = $1 AND tenant_id = $2`,
        [id, user.tenantId],
      );
      if (current.rows.length === 0) {
        await client.query('ROLLBACK');
        throw notFound('漏洞不存在');
      }
      const prev = current.rows[0];

      const sets: string[] = [];
      const params: unknown[] = [];
      if (parsed.data.status && parsed.data.status !== prev.status) {
        params.push(parsed.data.status);
        sets.push(`status = $${params.length}::finding_status_enum`);
      }
      if (parsed.data.severity && parsed.data.severity !== prev.severity) {
        params.push(parsed.data.severity);
        sets.push(`severity = $${params.length}::severity_enum`);
      }
      if (sets.length === 0) {
        await client.query('ROLLBACK');
        return c.json({ unchanged: true });
      }
      sets.push('updated_at = NOW()');
      params.push(id, user.tenantId);
      const { rows } = await client.query(
        `UPDATE detection.findings SET ${sets.join(', ')}
         WHERE id = $${params.length - 1} AND tenant_id = $${params.length}
         RETURNING id, status, severity, updated_at`,
        params,
      );

      if (parsed.data.status && parsed.data.status !== prev.status) {
        await client.query(
          `INSERT INTO detection.finding_state_history
             (tenant_id, customer_id, finding_id, from_status, to_status, change_source, changed_by, reason)
           VALUES ($1, (SELECT customer_id FROM detection.findings WHERE id = $2), $2, $3, $4, 'manual'::state_change_source_enum, $5, $6)`,
          [user.tenantId, id, prev.status, parsed.data.status, user.id, parsed.data.reason ?? null],
        );
      }

      await client.query('COMMIT');
      return c.json(rows[0]);
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })
  .post('/bulk', async (c) => {
    requireRole(c, PROVIDER_WRITE_ROLES);
    const user = c.get('user');
    const body = await c.req.json().catch(() => ({}));
    const parsed = bulkSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const targetStatus = parsed.data.action === 'triage' ? 'in_progress'
      : parsed.data.action === 'false_positive' ? 'false_positive'
      : parsed.data.action === 'accepted_risk' ? 'accepted_risk'
      : 'escalated';

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL app.current_tenant = '${user.tenantId}'`);
      await client.query(`SET LOCAL app.current_user_role = '${user.role}'`);

      const { rows: prev } = await client.query(
        `SELECT id, status FROM detection.findings WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
        [user.tenantId, parsed.data.ids],
      );
      if (prev.length === 0) {
        await client.query('ROLLBACK');
        throw notFound('所选漏洞不存在');
      }

      const { rowCount } = await client.query(
        `UPDATE detection.findings
         SET status = $1::finding_status_enum, updated_at = NOW()
         WHERE tenant_id = $2 AND id = ANY($3::uuid[])`,
        [targetStatus, user.tenantId, parsed.data.ids],
      );

      for (const p of prev) {
        if (p.status === targetStatus) continue;
        await client.query(
          `INSERT INTO detection.finding_state_history
             (tenant_id, customer_id, finding_id, from_status, to_status, change_source, changed_by, reason)
           VALUES ($1, (SELECT customer_id FROM detection.findings WHERE id = $2), $2, $3, $4, 'bulk_update'::state_change_source_enum, $5, $6)`,
          [user.tenantId, p.id, p.status, targetStatus, user.id, parsed.data.reason ?? null],
        );
      }

      await client.query('COMMIT');
      return c.json({ updated: rowCount, targetStatus });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })
  .post('/:id/comments', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const body = await c.req.json().catch(() => ({}));
    const parsed = commentSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const pg = c.get('pg');
    const { rows: finding } = await pg.query(
      `SELECT id, customer_id FROM detection.findings WHERE id = $1 AND tenant_id = $2`,
      [id, user.tenantId],
    );
    if (finding.length === 0) throw notFound('漏洞不存在');

    const { rows } = await pg.query(
      `INSERT INTO detection.finding_comments
         (tenant_id, customer_id, finding_id, author_user_id, comment_type, body, mentioned_user_ids)
       VALUES ($1, $2, $3, $4, $5::comment_type_enum, $6, $7::uuid[])
       RETURNING id, comment_type, body, author_user_id, created_at`,
      [user.tenantId, finding[0].customer_id, id, user.id, parsed.data.type, parsed.data.body, parsed.data.mention_user_ids ?? []],
    );
    return c.json(rows[0], 201);
  })
  .post('/:id/escalate', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const body = await c.req.json().catch(() => ({}));
    const ticketIntegrationId = body.ticket_integration_id;
    const note = body.note ?? null;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL app.current_tenant = '${user.tenantId}'`);
      await client.query(`SET LOCAL app.current_user_role = '${user.role}'`);

      const { rows: finding } = await client.query(
        `SELECT id, customer_id, status, title, severity, file_path
         FROM detection.findings WHERE id = $1 AND tenant_id = $2`,
        [id, user.tenantId],
      );
      if (finding.length === 0) {
        await client.query('ROLLBACK');
        throw notFound('漏洞不存在');
      }
      const f = finding[0];

      if (f.status !== 'escalated') {
        await client.query(
          `UPDATE detection.findings SET status = 'escalated', updated_at = NOW() WHERE id = $1`,
          [id],
        );
        await client.query(
          `INSERT INTO detection.finding_state_history
             (tenant_id, customer_id, finding_id, from_status, to_status, change_source, changed_by, reason)
           VALUES ($1, $2, $3, $4, 'escalated'::finding_status_enum, 'manual'::state_change_source_enum, $5, $6)`,
          [user.tenantId, f.customer_id, id, f.status, user.id, note],
        );
      }

      let pushResult: { pushed: boolean; externalRef?: string; error?: string } = { pushed: false };
      if (ticketIntegrationId) {
        pushResult = { pushed: false, error: '工单推送服务(P2.3)在下一阶段上线' };
      }

      await client.query('COMMIT');
      return c.json({ escalated: true, ticketPush: pushResult });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })
  .post('/:id/ai-explain', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, severity, title, file_path, start_line, code_snippet, cwe_ids
       FROM detection.findings WHERE id = $1 AND tenant_id = $2`,
      [id, user.tenantId],
    );
    if (rows.length === 0) throw notFound('漏洞不存在');
    const f = rows[0];

    return c.json({
      explanation: `这是一个 ${f.severity.toUpperCase()} 级别漏洞:${f.title}。位于 ${f.file_path} 第 ${f.start_line} 行。CWE:${(f.cwe_ids ?? []).join(', ')}。\n\n修复建议:对用户输入进行严格校验,使用参数化查询,避免直接拼接。详细分析待 LLM 集成(P4.1)后提供更深度解释。`,
      aiBypassed: true,
      model: 'rule-template',
      usageTokens: 0,
    });
  })
  .post('/:id/ai-triage', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, severity, status, title, code_snippet, confidence FROM detection.findings WHERE id = $1 AND tenant_id = $2`,
      [id, user.tenantId],
    );
    if (rows.length === 0) throw notFound('漏洞不存在');
    const f = rows[0];

    return c.json({
      hint: '基于规则的预筛判断:低风险疑似误报(详细判断待 P4.1 AI)',
      confidence: f.confidence ?? 'medium',
      suggestedAction: f.confidence === 'low' ? 'false_positive' : 'in_progress',
      aiBypassed: true,
    });
  });