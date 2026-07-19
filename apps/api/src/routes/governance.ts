import { Hono } from 'hono';
import { createHash } from 'node:crypto';
import { pool } from '../db/client';
import { requireRole, PROVIDER_ADMIN_ROLES } from '../middleware/rbac';

const AUDIT_CSV_COLUMNS = [
  'occurred_at',
  'event_type',
  'actor_email',
  'actor_ip',
  'resource_type',
  'resource_id',
  'action',
  'request_id',
  'prev_hash',
  'entry_hash',
] as const;

function csvEscape(value: unknown): string {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (s.includes('"') || s.includes(',') || s.includes('\n') || s.includes('\r')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function rowToCsv(row: Record<string, unknown>): string {
  return AUDIT_CSV_COLUMNS.map((c) => csvEscape(row[c])).join(',');
}

export const governanceRoutes = new Hono()
  .get('/compliance', async (c) => {
    const pg = c.get('pg');
    const { rows: frameworks } = await pg.query(
      `SELECT key, value, updated_at
       FROM meta.app_settings
       WHERE key IN ('compliance_owasp', 'compliance_iso27001', 'compliance_soc2', 'compliance_gdpr')
       ORDER BY key`,
    );
    return c.json({
      frameworks: frameworks.map((r: any) => ({ name: r.key, config: r.value, updatedAt: r.updated_at })),
      summary: {
        totalFrameworks: frameworks.length,
        enabled: frameworks.filter((r: any) => (r.value as any)?.enabled === true).length,
        lastAuditAt: frameworks[0]?.updated_at ?? null,
      },
    });
  })
  .get('/audit', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const pg = c.get('pg');
    const actor = c.req.query('actor');
    const resourceType = c.req.query('resource_type');
    const params: unknown[] = [c.get('user').tenantId];
    let where = 'tenant_id = $1';
    if (actor) { params.push(`%${actor}%`); where += ` AND actor_email ILIKE $${params.length}`; }
    if (resourceType) { params.push(resourceType); where += ` AND resource_type = $${params.length}`; }
    const { rows } = await pg.query(
      `SELECT id, occurred_at, actor_user_id, actor_email, actor_ip,
              event_type, resource_type, resource_id, action, request_id, metadata
       FROM governance.audit_logs
       WHERE ${where}
       ORDER BY occurred_at DESC
       LIMIT 200`,
      params,
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, occurredAt: r.occurred_at, actorUserId: r.actor_user_id, actorEmail: r.actor_email,
        actorIp: r.actor_ip, eventType: r.event_type, resourceType: r.resource_type,
        resourceId: r.resource_id, action: r.action, requestId: r.request_id, metadata: r.metadata,
      })),
    });
  })
  .get('/audit/export', async (c) => {
    const pg = c.get('pg');
    const format = (c.req.query('format') ?? 'json').toLowerCase();
    const since = c.req.query('since');
    const until = c.req.query('until');
    const params: unknown[] = [c.get('user').tenantId];
    let where = 'tenant_id = $1';
    if (since) { params.push(since); where += ` AND occurred_at >= $${params.length}::timestamptz`; }
    if (until) { params.push(until); where += ` AND occurred_at <= $${params.length}::timestamptz`; }
    const { rows } = await pg.query(
      `SELECT id, occurred_at, actor_email, actor_ip, actor_user_agent,
              event_type, resource_type, resource_id, action, request_id,
              metadata, prev_hash, entry_hash, occurred_at
       FROM governance.audit_logs
       WHERE ${where}
       ORDER BY occurred_at ASC, id ASC`,
      params,
    );

    if (format === 'csv') {
      const header = AUDIT_CSV_COLUMNS.join(',');
      const body = rows.map((r: any) => rowToCsv({
        occurred_at: r.occurred_at,
        event_type: r.event_type,
        actor_email: r.actor_email,
        actor_ip: r.actor_ip,
        resource_type: r.resource_type,
        resource_id: r.resource_id,
        action: r.action,
        request_id: r.request_id,
        prev_hash: r.prev_hash?.toString('hex'),
        entry_hash: r.entry_hash?.toString('hex'),
      })).join('\n');
      const csv = `${header}\n${body}\n`;
      const sha256 = createHash('sha256').update(csv).digest('hex');
      const filename = `audit-${c.get('user').tenantId}-${Date.now()}.csv`;
      c.header('Content-Type', 'text/csv; charset=utf-8');
      c.header('Content-Disposition', `attachment; filename="${filename}"`);
      c.header('X-Audit-SHA256', sha256);
      c.header('X-Audit-Row-Count', String(rows.length));
      return c.body(csv);
    }

    const sha256 = createHash('sha256')
      .update(JSON.stringify(rows))
      .digest('hex');
    return c.json({
      tenantId: c.get('user').tenantId,
      exportedAt: new Date().toISOString(),
      rowCount: rows.length,
      sha256,
      filter: { since: since ?? null, until: until ?? null },
      items: rows.map((r: any) => ({
        id: r.id,
        occurredAt: r.occurred_at,
        actorEmail: r.actor_email,
        actorIp: r.actor_ip,
        actorUserAgent: r.actor_user_agent,
        eventType: r.event_type,
        resourceType: r.resource_type,
        resourceId: r.resource_id,
        action: r.action,
        requestId: r.request_id,
        metadata: r.metadata,
        prevHash: r.prev_hash?.toString('hex'),
        entryHash: r.entry_hash?.toString('hex'),
      })),
    });
  })
  .get('/audit/integrity', async (c) => {
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `WITH ordered AS (
         SELECT id, occurred_at, tenant_id, prev_hash, entry_hash,
                lag(entry_hash) OVER (PARTITION BY tenant_id ORDER BY occurred_at, id) AS expected_prev,
                row_number() OVER (PARTITION BY tenant_id ORDER BY occurred_at, id) AS rn
         FROM governance.audit_logs
         WHERE tenant_id = $1
       )
       SELECT id, occurred_at, prev_hash, entry_hash, expected_prev, rn,
              (rn = 1 AND prev_hash = decode(repeat('0', 64), 'hex'))
                OR (rn > 1 AND expected_prev IS NOT DISTINCT FROM prev_hash) AS link_ok
       FROM ordered
       ORDER BY occurred_at, id`,
      [c.get('user').tenantId],
    );
    const total = rows.length;
    const broken = rows.filter((r: any) => !r.link_ok);
    return c.json({
      tenantId: c.get('user').tenantId,
      totalEntries: total,
      intact: broken.length === 0,
      brokenLinks: broken.map((r: any) => ({
        id: r.id,
        occurredAt: r.occurred_at,
        prevHash: r.prev_hash?.toString('hex'),
        expectedPrev: r.expected_prev?.toString('hex') ?? null,
        entryHash: r.entry_hash?.toString('hex'),
        position: r.rn,
      })),
      verifiedAt: new Date().toISOString(),
    });
  })
  .get('/team', async (c) => {
    requireRole(c, PROVIDER_ADMIN_ROLES);
    const pg = c.get('pg');
    const { rows: members } = await pg.query(
      `SELECT u.id, u.email, u.full_name, u.role, u.status, u.last_login_at, u.created_at,
              EXISTS(SELECT 1 FROM core.invites i WHERE i.email = u.email AND i.status = 'pending') as has_pending_invite
       FROM core.users u
       WHERE u.tenant_id = $1
       ORDER BY u.role, u.email`,
      [c.get('user').tenantId],
    );
    const { rows: invites } = await pg.query(
      `SELECT id, email, role, status, invited_by, expires_at, created_at
       FROM core.invites
       WHERE tenant_id = $1 AND status = 'pending' AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [c.get('user').tenantId],
    );
    return c.json({
      members: members.map((r: any) => ({
        id: r.id, email: r.email, fullName: r.full_name, role: r.role, status: r.status,
        lastLoginAt: r.last_login_at, createdAt: r.created_at, hasPendingInvite: r.has_pending_invite,
      })),
      pendingInvites: invites.map((r: any) => ({
        id: r.id, email: r.email, role: r.role, invitedBy: r.invited_by,
        expiresAt: r.expires_at, createdAt: r.created_at,
      })),
    });
  })
  .get('/integrations', async (c) => {
    const pg = c.get('pg');
    const { rows: webhooks } = await pg.query(
      `SELECT id, url, event_types, enabled, created_at,
              (SELECT count(*) FROM governance.webhook_deliveries WHERE webhook_id = w.id AND status = 'success')::int as delivered_count,
              (SELECT count(*) FROM governance.webhook_deliveries WHERE webhook_id = w.id AND status = 'failed')::int as failed_count,
              (SELECT max(delivered_at) FROM governance.webhook_deliveries WHERE webhook_id = w.id) as last_delivered_at
       FROM governance.webhooks w
       WHERE tenant_id = $1 AND deleted_at IS NULL
       ORDER BY created_at DESC`,
      [c.get('user').tenantId],
    );
    return c.json({
      items: webhooks.map((r: any) => ({
        id: r.id, url: r.url, eventTypes: r.event_types, enabled: r.enabled,
        createdAt: r.created_at, deliveredCount: r.delivered_count, failedCount: r.failed_count,
        lastDeliveredAt: r.last_delivered_at,
      })),
    });
  });

export const gdprRoutes = new Hono()
  .get('/gdpr/status', async (c) => {
    const pg = c.get('pg');
    const tenantId = c.get('user').tenantId;
    const { rows: recent } = await pg.query(
      `SELECT id, request_type, status, requested_at, completed_at, artifact_expires_at
       FROM governance.tenant_data_exports
       WHERE tenant_id = $1
       ORDER BY requested_at DESC
       LIMIT 20`,
      [tenantId],
    );
    const { rows: counts } = await pg.query(
      `SELECT request_type, status, count(*)::int AS count
       FROM governance.tenant_data_exports
       WHERE tenant_id = $1 AND requested_at >= NOW() - INTERVAL '30 days'
       GROUP BY request_type, status`,
      [tenantId],
    );
    return c.json({
      tenantId,
      retentionDays: 30,
      retentionNote: '30 天软删除恢复窗口;到期后硬删除不可恢复',
      recentRequests: recent.map((r: any) => ({
        id: r.id,
        requestType: r.request_type,
        status: r.status,
        requestedAt: r.requested_at,
        completedAt: r.completed_at,
        artifactExpiresAt: r.artifact_expires_at,
      })),
      last30DaysBreakdown: counts,
    });
  })
  .post('/gdpr/request', async (c) => {
    const pg = c.get('pg');
    const tenantId = c.get('user').tenantId;
    const userId = c.get('user').id;
    const body = await c.req.json().catch(() => ({}));
    const requestType = body.requestType ?? body.type ?? 'customer_export';
    const customerId = body.customerId ?? null;
    const allowed = ['customer_export', 'customer_delete', 'project_export', 'tenant_full_export'];
    if (!allowed.includes(requestType)) {
      return c.json({ error: { code: 'bad_request', message: `requestType must be one of ${allowed.join(',')}` } }, 400);
    }
    const scope = {
      tenantId,
      customerId,
      requesterUserId: userId,
      requestedVia: 'api',
      requestedAt: new Date().toISOString(),
    };
    const { rows } = await pg.query(
      `INSERT INTO governance.tenant_data_exports
         (tenant_id, customer_id, request_type, requested_by, status, scope)
       VALUES ($1, $2, $3::data_export_type_enum, $4, 'pending', $5::jsonb)
       RETURNING id, request_type, status, requested_at, scope`,
      [tenantId, customerId, requestType, userId, JSON.stringify(scope)],
    );
    const inserted = rows[0];
    return c.json({
      id: inserted.id,
      requestType: inserted.request_type,
      status: inserted.status,
      requestedAt: inserted.requested_at,
      scope: inserted.scope,
      message: 'request 已记录;30 天保留窗口内可在 status 接口查看进度或撤回',
    }, 201);
  })
  .get('/gdpr/download/:exportId', async (c) => {
    const pg = c.get('pg');
    const exportId = c.req.param('exportId');
    const { rows } = await pg.query(
      `SELECT id, request_type, status, requested_at, completed_at, artifact_expires_at,
              artifact_uri, artifact_sha256, artifact_size_bytes, record_counts, error_message
       FROM governance.tenant_data_exports
       WHERE id = $1 AND tenant_id = $2`,
      [exportId, c.get('user').tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found' } }, 404);
    const exp = rows[0];
    if (exp.status !== 'ready') {
      return c.json({ error: { code: 'not_ready', status: exp.status } }, 409);
    }
    if (exp.artifact_expires_at && new Date(exp.artifact_expires_at) < new Date()) {
      return c.json({ error: { code: 'expired', expiresAt: exp.artifact_expires_at } }, 410);
    }
    return c.json({
      id: exp.id,
      requestType: exp.request_type,
      status: exp.status,
      requestedAt: exp.requested_at,
      completedAt: exp.completed_at,
      artifactExpiresAt: exp.artifact_expires_at,
      artifactSha256: exp.artifact_sha256,
      artifactSizeBytes: exp.artifact_size_bytes,
      recordCounts: exp.record_counts,
      artifactUri: exp.artifact_uri,
      message: 'artifact URI 由对象存储后端解析 (/gdpr/file/:id 可流式下载)',
    });
  })
  .get('/gdpr/file/:exportId', async (c) => {
    const pg = c.get('pg');
    const exportId = c.req.param('exportId');
    const { rows } = await pg.query(
      `SELECT id, request_type, status, scope, record_counts
       FROM governance.tenant_data_exports
       WHERE id = $1 AND tenant_id = $2`,
      [exportId, c.get('user').tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found' } }, 404);
    const exp = rows[0];
    if (exp.status !== 'ready') {
      return c.json({ error: { code: 'not_ready', status: exp.status } }, 409);
    }
    const { rows: dataRows } = await pg.query(
      `SELECT id, email, full_name, role, status, created_at, deleted_at
       FROM core.users
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [c.get('user').tenantId],
    );
    const { rows: customerRows } = await pg.query(
      `SELECT id, name, slug, status, created_at, deleted_at
       FROM core.customers
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [c.get('user').tenantId],
    );
    const payload = {
      exportId: exp.id,
      requestType: exp.request_type,
      scope: exp.scope,
      recordCounts: {
        users: dataRows.length,
        customers: customerRows.length,
      },
      data: {
        users: dataRows,
        customers: customerRows,
      },
      generatedAt: new Date().toISOString(),
    };
    c.header('Content-Type', 'application/json; charset=utf-8');
    c.header('Content-Disposition', `attachment; filename="gdpr-export-${exp.id}.json"`);
    return c.body(JSON.stringify(payload, null, 2));
  });
