import { Hono } from 'hono';
import { pool } from '../db/client';

export const workbenchRoutes = new Hono()
  .get('/overview', async (c) => {
    const pg = c.get('pg');
    const tenantId = c.get('user').tenantId;

    const [usageRes, findingsRes, pocRes, scanRes] = await Promise.all([
      pg.query(
        `SELECT COALESCE(SUM(total_tokens), 0) AS tokens
         FROM usage.usage_events
         WHERE tenant_id = $1 AND occurred_at >= date_trunc('month', NOW())`,
        [tenantId],
      ),
      pg.query(
        `SELECT
           count(*) FILTER (WHERE severity = 'critical' AND status IN ('open','in_progress','escalated')) AS critical,
           count(*) FILTER (WHERE severity = 'high' AND status IN ('open','in_progress','escalated')) AS high
         FROM detection.findings
         WHERE tenant_id = $1`,
        [tenantId],
      ),
      pg.query(
        `SELECT
           count(*) FILTER (WHERE status = 'pending') AS pending,
           count(*) FILTER (WHERE status = 'approved') AS approved,
           count(*) FILTER (WHERE status = 'running') AS running
         FROM poc.poc_runs
         WHERE tenant_id = $1`,
        [tenantId],
      ),
      pg.query(
        `SELECT
           count(*) FILTER (WHERE status = 'running') AS running,
           count(*) FILTER (WHERE status = 'queued') AS queued
         FROM detection.scan_runs
         WHERE tenant_id = $1`,
        [tenantId],
      ),
    ]);

    const usage = Number(usageRes.rows[0]?.tokens ?? 0);
    const crit = Number(findingsRes.rows[0]?.critical ?? 0);
    const high = Number(findingsRes.rows[0]?.high ?? 0);
    const pocTotal = Number(pocRes.rows[0]?.pending ?? 0) + Number(pocRes.rows[0]?.approved ?? 0);
    const scanRunning = Number(scanRes.rows[0]?.running ?? 0);
    const scanQueued = Number(scanRes.rows[0]?.queued ?? 0);

    return c.json({
      kpis: [
        {
          key: 'usage',
          label: '本月用量',
          value: usage,
          unit: 'tokens',
          change_pct: 0,
          secondary: `CRIT ${crit}`,
          action: '/billing/usage',
        },
        {
          key: 'critical_findings',
          label: '高危 Findings',
          value: crit + high,
          change: `CRIT ${crit} / HIGH ${high}`,
          action: '/findings?severity=critical',
        },
        {
          key: 'pending_poc',
          label: '待验证 PoC',
          value: pocTotal,
          badge: '待审 ' + pocRes.rows[0]?.pending,
          action: '/validation/queue',
        },
        {
          key: 'scan_queue',
          label: '扫描队列',
          value: `${scanRunning} 运行 / ${scanQueued} 排队`,
          action: '/detection/queue',
        },
      ],
      top_customers: [],
      refreshed_at: new Date().toISOString(),
    });
  });
