import { Hono } from 'hono';
import { ApiError } from '../middleware/error';
import { requireRole, CUSTOMER_ADMIN_ROLES, CUSTOMER_WRITE_ROLES, type AuthUser } from '../middleware/rbac';

function requireCustomer(user: { portal: string; customerId?: string } | undefined) {
  if (!user || user.portal !== 'customer' || !user.customerId) {
    throw new ApiError(403, 'wrong_portal', 'Customer portal required - please log in via customer portal');
  }
}

export const customerRoutes = new Hono()
  .get('/dashboard', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const customerId = user.customerId!;
    const pg = c.get('pg');

    const [kpiRes, recentRes] = await Promise.all([
      pg.query(
        `SELECT
           (SELECT count(*) FROM detection.findings
            WHERE customer_id = $1 AND status IN ('open','in_progress','escalated') AND severity = 'critical')::int as critical,
           (SELECT count(*) FROM detection.findings
            WHERE customer_id = $1 AND status IN ('open','in_progress','escalated') AND severity = 'high')::int as high,
           (SELECT count(*) FROM detection.findings
            WHERE customer_id = $1 AND status = 'confirmed')::int as confirmed,
           (SELECT count(*) FROM detection.scan_runs
            WHERE customer_id = $1 AND created_at > NOW() - INTERVAL '7 days')::int as recent_scans`,
        [customerId],
      ),
      pg.query(
        `SELECT id, title, severity, status, file_path, last_seen_at
         FROM detection.findings
         WHERE customer_id = $1 AND status IN ('open','in_progress','escalated')
         ORDER BY
           CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
           last_seen_at DESC
         LIMIT 10`,
        [customerId],
      ),
    ]);

    return c.json({
      kpis: {
        criticalFindings: kpiRes.rows[0]?.critical ?? 0,
        highFindings: kpiRes.rows[0]?.high ?? 0,
        confirmedExploits: kpiRes.rows[0]?.confirmed ?? 0,
        recentScans: kpiRes.rows[0]?.recent_scans ?? 0,
      },
      recentFindings: recentRes.rows.map((r: any) => ({
        id: r.id, title: r.title, severity: r.severity, status: r.status,
        filePath: r.file_path, lastSeenAt: r.last_seen_at,
      })),
    });
  })
  .get('/projects', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const customerId = user.customerId!;
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT p.id, p.name, p.slug, p.status, p.sla_tier, p.default_branch, p.created_at,
              (SELECT count(*) FROM detection.scan_runs WHERE project_id = p.id AND status = 'done')::int as total_scans,
              (SELECT max(started_at) FROM detection.scan_runs WHERE project_id = p.id) as last_scan_at,
              (SELECT count(*) FROM detection.findings WHERE project_id = p.id AND status IN ('open','in_progress','escalated'))::int as open_findings
       FROM core.projects p
       WHERE p.customer_id = $1 AND p.deleted_at IS NULL
       ORDER BY p.created_at DESC`,
      [customerId],
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, name: r.name, slug: r.slug, status: r.status, slaTier: r.sla_tier,
        defaultBranch: r.default_branch, createdAt: r.created_at,
        totalScans: r.total_scans, lastScanAt: r.last_scan_at, openFindings: r.open_findings,
      })),
    });
  })
  .get('/projects/:id', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const customerId = user.customerId!;
    const id = c.req.param('id');
    const pg = c.get('pg');
    const { rows: pRows } = await pg.query(
      `SELECT p.id, p.name, p.slug, p.description, p.status, p.sla_tier, p.default_branch,
              p.branch_policy, p.created_at, p.data_retention_days,
              (SELECT count(*) FROM detection.findings WHERE project_id = p.id)::int as total_findings,
              (SELECT count(*) FROM detection.findings WHERE project_id = p.id AND status IN ('open','in_progress','escalated'))::int as open_findings
       FROM core.projects p
       WHERE p.id = $1 AND p.customer_id = $2 AND p.deleted_at IS NULL`,
      [id, customerId],
    );
    if (pRows.length === 0) return c.json({ error: { code: 'not_found', message: 'Project not found' } }, 404);
    const p = pRows[0];
    const { rows: scanRows } = await pg.query(
      `SELECT id, trigger_type, status, started_at, finished_at, duration_ms,
              findings_total, findings_new, findings_fixed
       FROM detection.scan_runs WHERE project_id = $1
       ORDER BY created_at DESC LIMIT 20`,
      [id],
    );
    return c.json({
      ...p,
      totalScans: scanRows.length,
      scans: scanRows,
    });
  })
  .get('/findings', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const customerId = user.customerId!;
    const pg = c.get('pg');
    const severity = c.req.query('severity');
    const status = c.req.query('status');
    const projectId = c.req.query('project_id');
    const params: unknown[] = [customerId];
    let where = 'f.customer_id = $1';
    if (severity) { params.push(severity); where += ` AND f.severity = $${params.length}::severity_enum`; }
    if (status) { params.push(status); where += ` AND f.status = $${params.length}::finding_status_enum`; }
    if (projectId) { params.push(projectId); where += ` AND f.project_id = $${params.length}::uuid`; }
    const { rows } = await pg.query(
      `SELECT f.id, f.title, f.severity, f.status, f.file_path, f.start_line, f.end_line,
              f.cwe_ids, f.first_seen_at, f.last_seen_at, p.name as project_name,
              (SELECT exploit_proven FROM poc.poc_runs WHERE finding_id = f.id AND exploit_proven = true LIMIT 1) as has_poc_proof
       FROM detection.findings f
       LEFT JOIN core.projects p ON p.id = f.project_id
       WHERE ${where}
       ORDER BY
         CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
         f.last_seen_at DESC
       LIMIT 200`,
      params,
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, title: r.title, severity: r.severity, status: r.status,
        filePath: r.file_path, startLine: r.start_line, endLine: r.end_line,
        cweIds: r.cwe_ids, firstSeenAt: r.first_seen_at, lastSeenAt: r.last_seen_at,
        projectName: r.project_name, hasPocProof: !!r.has_poc_proof,
      })),
    });
  })
  .get('/findings/:id', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const customerId = user.customerId!;
    const id = c.req.param('id');
    const pg = c.get('pg');
    const { rows: fRows } = await pg.query(
      `SELECT f.id, f.title, f.description, f.severity, f.status, f.file_path, f.start_line, f.end_line,
              f.code_snippet, f.cwe_ids, f.owasp_ids, f.confidence, f.engines,
              f.dfg_path, f.first_seen_at, f.last_seen_at, f.confirmed_at, f.fixed_at,
              p.id as project_id, p.name as project_name,
              r.title as rule_title, r.description as rule_description
       FROM detection.findings f
       LEFT JOIN core.projects p ON p.id = f.project_id
       LEFT JOIN detection.rules r ON r.id = f.rule_id
       WHERE f.id = $1 AND f.customer_id = $2`,
      [id, customerId],
    );
    if (fRows.length === 0) return c.json({ error: { code: 'not_found' } }, 404);
    const f = fRows[0];
    const { rows: stateRows } = await pg.query(
      `SELECT from_status, to_status, change_source, changed_by, reason, occurred_at
       FROM detection.finding_state_history
       WHERE finding_id = $1
       ORDER BY occurred_at ASC
       LIMIT 50`,
      [id],
    );
    const { rows: pocs } = await pg.query(
      `SELECT id, status, exploit_proven, started_at, finished_at, duration_ms, exit_code
       FROM poc.poc_runs WHERE finding_id = $1
       ORDER BY created_at DESC
       LIMIT 5`,
      [id],
    );
    const { rows: comments } = await pg.query(
      `SELECT id, author_user_id, body, comment_type, created_at
       FROM detection.finding_comments
       WHERE finding_id = $1 AND deleted_at IS NULL
       ORDER BY created_at ASC`,
      [id],
    );
    return c.json({
      ...f, stateHistory: stateRows, pocRuns: pocs, comments,
    });
  })
  .get('/reports', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const customerId = user.customerId!;
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, report_type, format, period_start, period_end, file_size_bytes,
              generated_by, status, created_at
       FROM core.reports
       WHERE customer_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [customerId],
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, reportType: r.report_type, format: r.format,
        periodStart: r.period_start, periodEnd: r.period_end, fileSizeBytes: r.file_size_bytes,
        generatedBy: r.generated_by, status: r.status, createdAt: r.created_at,
      })),
    });
  })
  .get('/reports/:id/download', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const reportId = c.req.param('id');
    const customerId = user.customerId!;
    const pg = c.get('pg');
    const { rows } = await pg.query(
      // NOTE: core.reports has no artifact_sha256 column (verified
      // 2026-07-05 via information_schema) — only file_object_key +
      // file_size_bytes. Referencing the missing column returned 500.
      `SELECT id, report_type, format, period_start, period_end,
              file_object_key, file_size_bytes, status
       FROM core.reports
       WHERE id = $1 AND customer_id = $2`,
      [reportId, customerId],
    );
    if (rows.length === 0) {
      throw new ApiError(404, 'not_found', '报告不存在或无权访问');
    }
    const r = rows[0] as any;
    // pg returns bigint as string — coerce to Number for JSON consumers
    // (frontend formatters assume number, not string).
    const fileSizeBytes = r.file_size_bytes == null
      ? null
      : Number(r.file_size_bytes);
    return c.json({
      id: r.id,
      reportType: r.report_type,
      format: r.format,
      periodStart: r.period_start,
      periodEnd: r.period_end,
      fileSizeBytes,
      status: r.status,
      message: '生产环境: 通过预签 URL 从对象存储下载;开发环境: 联系服务商重新生成',
      objectKey: r.file_object_key,
    });
  })
  .get('/usage', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const customerId = user.customerId!;
    const pg = c.get('pg');
    const { rows: total } = await pg.query(
      `SELECT
         count(*)::int as event_count,
         COALESCE(sum(total_tokens), 0)::bigint as total_tokens,
         COALESCE(sum(cost_usd), 0)::numeric as total_cost
       FROM usage.usage_events WHERE customer_id = $1`,
      [customerId],
    );
    const { rows: byCap } = await pg.query(
      `SELECT capability, sum(total_tokens)::bigint as tokens
       FROM usage.usage_events WHERE customer_id = $1
       GROUP BY capability ORDER BY tokens DESC`,
      [customerId],
    );
    const { rows: byDay } = await pg.query(
      `SELECT date_trunc('day', occurred_at)::date as day, sum(total_tokens)::bigint as tokens
       FROM usage.usage_events WHERE customer_id = $1 AND occurred_at > NOW() - INTERVAL '30 days'
       GROUP BY day ORDER BY day`,
      [customerId],
    );
    const { rows: quotaRows } = await pg.query(
      `SELECT ba.plan, ba.monthly_token_quota, ba.balance_usd
       FROM billing.billing_accounts ba WHERE ba.customer_id = $1 LIMIT 1`,
      [customerId],
    );
    return c.json({
      totals: {
        eventCount: total[0]?.event_count ?? 0,
        totalTokens: Number(total[0]?.total_tokens ?? 0),
        totalCost: Number(total[0]?.total_cost ?? 0),
      },
      byCapability: byCap.map((r: any) => ({ capability: r.capability, tokens: Number(r.tokens) })),
      byDay: byDay.map((r: any) => ({ day: r.day, tokens: Number(r.tokens) })),
      quota: quotaRows[0] ? {
        plan: quotaRows[0].plan,
        monthlyTokenQuota: Number(quotaRows[0].monthly_token_quota),
        balanceUsd: Number(quotaRows[0].balance_usd),
      } : null,
    });
  })
  .get('/settings/members', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    requireRole(c, CUSTOMER_ADMIN_ROLES);
    const customerId = user.customerId!;
    const pg = c.get('pg');
    const { rows: members } = await pg.query(
      `SELECT u.id, u.email, u.full_name, u.role, u.status, u.last_login_at
       FROM core.users u
       WHERE u.customer_id = $1
       ORDER BY u.role, u.email`,
      [customerId],
    );
    const { rows: invites } = await pg.query(
      `SELECT id, email, role, expires_at, created_at
       FROM core.invites
       WHERE customer_id = $1 AND status = 'pending' AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [customerId],
    );
    return c.json({
      members: members.map((r: any) => ({
        id: r.id, email: r.email, fullName: r.full_name, role: r.role, status: r.status,
        lastLoginAt: r.last_login_at,
      })),
      pendingInvites: invites.map((r: any) => ({
        id: r.id, email: r.email, role: r.role, expiresAt: r.expires_at, createdAt: r.created_at,
      })),
    });
  })
  .get('/settings/integrations', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    requireRole(c, CUSTOMER_ADMIN_ROLES);
    const customerId = user.customerId!;
    const pg = c.get('pg');
    const { rows: webhooks } = await pg.query(
      `SELECT id, url, event_types, enabled, created_at
       FROM governance.webhooks
       WHERE customer_id = $1 AND deleted_at IS NULL
       ORDER BY created_at DESC`,
      [customerId],
    );
    const { rows: tickets } = await pg.query(
      `SELECT id, system, display_name, api_base_url, project_key, repo_full_name,
              enabled, created_at
       FROM integration.ticket_integrations
       WHERE customer_id = $1 AND deleted_at IS NULL
       ORDER BY created_at DESC`,
      [customerId],
    );
    return c.json({ webhooks, ticketIntegrations: tickets });
  })
  .get('/settings/notifications', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT notification_prefs FROM core.users WHERE id = $1`,
      [user.id],
    );
    return c.json(rows[0]?.notification_prefs ?? {});
  })
  .put('/settings/notifications', async (c) => {
    const user = c.get('user');
    requireCustomer(user);
    requireRole(c, CUSTOMER_WRITE_ROLES);
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ error: { code: 'bad_request' } }, 400);
    const pg = c.get('pg');
    await pg.query(`UPDATE core.users SET notification_prefs = $1 WHERE id = $2`, [JSON.stringify(body), user.id]);
    return c.json({ ok: true });
  });

