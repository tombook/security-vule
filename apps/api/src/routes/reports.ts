import { Hono } from 'hono';
import { z } from 'zod';
import { createHash } from 'node:crypto';
import { pool } from '../db/client';
import { notFound } from '../middleware/error';

const reportSchema = z.object({
  type: z.enum(['weekly', 'monthly', 'single_finding', 'compliance', 'asset_snapshot']),
  customerId: z.string().uuid(),
  projectId: z.string().uuid().optional(),
  findingId: z.string().uuid().optional(),
  periodStart: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  periodEnd: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  format: z.enum(['html', 'pdf', 'markdown', 'json']).default('pdf'),
});

function buildMarkdownReport(opts: { type: string; period?: string; tenantName: string; whiteLabel: any; findings: any[]; projects: any[]; scans: any[] }): string {
  const md: string[] = [];
  const brand = opts.whiteLabel?.companyName ?? opts.tenantName;
  const primary = opts.whiteLabel?.primaryColor ?? '#0047AB';
  md.push(`# ${brand} - ${opts.type === 'weekly' ? '周' : opts.type === 'monthly' ? '月' : opts.type === 'compliance' ? '合规' : ''}报`);
  md.push(`> 报告期: ${opts.period ?? 'N/A'} · 生成时间: ${new Date().toISOString()}`);
  md.push('');
  md.push('## 概览');
  md.push(`| 指标 | 数量 |`);
  md.push(`| --- | --- |`);
  md.push(`| 项目 | ${opts.projects.length} |`);
  md.push(`| 扫描 | ${opts.scans.length} |`);
  md.push(`| 发现漏洞 | ${opts.findings.length} |`);
  const bySev = opts.findings.reduce<Record<string, number>>((m, f) => { m[f.severity] = (m[f.severity] ?? 0) + 1; return m; }, {});
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    md.push(`| ${sev.toUpperCase()} | ${bySev[sev] ?? 0} |`);
  }
  md.push('');
  md.push(`## 关键 Findings`);
  for (const f of opts.findings.filter((f) => ['critical', 'high'].includes(f.severity)).slice(0, 20)) {
    md.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
    md.push(`- 文件: \`${f.file_path}:${f.start_line}\``);
    md.push(`- 状态: ${f.status}`);
    if (f.cwe_ids?.length) md.push(`- CWE: ${f.cwe_ids.join(', ')}`);
    md.push('');
  }
  md.push('---');
  md.push(`*由 security-vule ${brand} 平台生成*`);
  return md.join('\n');
}

export const reportsRoutes = new Hono()
  .get('/', async (c) => {
    const user = c.get('user');
    const { rows } = await pool.query(
      `SELECT id, customer_id, project_id, finding_id, report_type, format,
              period_start, period_end, file_size_bytes, status, created_at
       FROM core.reports
       WHERE tenant_id = $1
       ORDER BY created_at DESC
       LIMIT 100`,
      [user.tenantId],
    );
    return c.json({ items: rows });
  })
  .post('/', async (c) => {
    const user = c.get('user');
    const body = await c.req.json().catch(() => ({}));
    const parsed = reportSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    const { type, customerId, projectId, findingId, periodStart, periodEnd, format } = parsed.data;

    const tenantRes = await pool.query(
      `SELECT name, white_label FROM core.tenants WHERE id = $1`,
      [user.tenantId],
    );
    const whiteLabel = tenantRes.rows[0]?.white_label ?? {};

    const where: string[] = ['tenant_id = $1'];
    const params: unknown[] = [user.tenantId];
    if (customerId) { params.push(customerId); where.push(`customer_id = $${params.length}`); }
    if (projectId) { params.push(projectId); where.push(`project_id = $${params.length}`); }
    if (findingId) { params.push(findingId); where.push(`id = $${params.length}`); }
    if (periodStart) { params.push(periodStart); where.push(`first_seen_at >= $${params.length}::date`); }
    if (periodEnd) { params.push(periodEnd); where.push(`first_seen_at <= $${params.length}::date`); }
    const whereClause = `WHERE ${where.join(' AND ')}`;

    const findings = await pool.query(
      `SELECT id, title, severity, status, file_path, start_line, cwe_ids
       FROM detection.findings ${whereClause}
       ORDER BY severity, last_seen_at DESC NULLS LAST
       LIMIT 200`,
      params,
    );
    const projects = await pool.query(
      `SELECT id, name FROM core.projects WHERE tenant_id = $1 LIMIT 100`,
      [user.tenantId],
    );
    const scans = await pool.query(
      `SELECT id, status, trigger_type FROM detection.scan_runs
       WHERE tenant_id = $1 AND ($2::uuid IS NULL OR customer_id = $2)
       ORDER BY created_at DESC LIMIT 50`,
      [user.tenantId, customerId ?? null],
    );

    const md = buildMarkdownReport({
      type, period: periodStart && periodEnd ? `${periodStart} ~ ${periodEnd}` : undefined,
      tenantName: tenantRes.rows[0]?.name ?? 'Tenant',
      whiteLabel, findings: findings.rows, projects: projects.rows, scans: scans.rows,
    });
    const content = format === 'markdown' ? md
      : format === 'json' ? JSON.stringify({ type, period: { start: periodStart, end: periodEnd }, findings: findings.rows }, null, 2)
      : format === 'html' ? `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${type} Report</title><style>body{font-family:sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#1A1A1A;background:#fff} h1{color:${whiteLabel?.primaryColor ?? '#0047AB'}} pre{background:#F5F7FA;padding:12px;border-radius:6px;overflow-x:auto}</style></head><body><pre>${md.replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c] ?? c))}</pre></body></html>`
      : md;

    const contentHash = createHash('sha256').update(content).digest('hex');
    const fileSize = Buffer.byteLength(content, 'utf-8');

    const { rows } = await pool.query(
      `INSERT INTO core.reports
         (tenant_id, customer_id, project_id, finding_id, report_type, format,
          period_start, period_end, file_object_key, file_size_bytes, generated_by, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7::date, $8::date, $9, $10, $11, 'ready')
       RETURNING id, report_type, format, period_start, period_end,
                 file_size_bytes, status, created_at`,
      [user.tenantId, customerId ?? null, projectId ?? null, findingId ?? null,
       type, format, periodStart ?? null, periodEnd ?? null,
       `reports/${user.tenantId.slice(0, 8)}/${Date.now()}.${format}`,
       fileSize, user.id],
    );
    return c.json({ ...rows[0], content, contentHash, sha256: contentHash }, 201);
  })
  .get('/:id/download', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const { rows: r } = await pool.query(
      `SELECT id, report_type, format, period_start, period_end, file_object_key, artifact_sha256
       FROM core.reports WHERE id = $1 AND tenant_id = $2`,
      [id, user.tenantId],
    );
    if (!r.length) throw notFound('报告不存在');
    return c.json({
      id: r[0].id,
      message: '生产环境: 通过预签 URL 从对象存储下载;开发环境: 通过 POST /reports 重新生成获得 content 字段',
      objectKey: r[0].file_object_key,
      sha256: r[0].artifact_sha256,
    });
  });