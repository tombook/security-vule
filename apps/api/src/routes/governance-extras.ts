import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';

const PERMISSION_MATRIX = {
  '客户管理(增删改)': { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '👁', ProviderViewer: '👁', CustomerAdmin: '❌', CustomerDeveloper: '❌', CustomerViewer: '❌' },
  '项目/扫描/Findings': { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '✅', ProviderViewer: '👁', CustomerAdmin: '✅', CustomerDeveloper: '✅', CustomerViewer: '👁' },
  'PoC 验证':         { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '✅', ProviderViewer: '👁', CustomerAdmin: '👁', CustomerDeveloper: '👁', CustomerViewer: '❌' },
  '计费/账单/配额':    { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '❌', ProviderViewer: '👁', CustomerAdmin: '👁', CustomerDeveloper: '❌', CustomerViewer: '❌' },
  '检测策略模板':      { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '✅', ProviderViewer: '👁', CustomerAdmin: '❌', CustomerDeveloper: '❌', CustomerViewer: '❌' },
  '团队成员管理':      { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '❌', ProviderViewer: '❌', CustomerAdmin: '❌', CustomerDeveloper: '❌', CustomerViewer: '❌' },
  '组织/API/通知设置':  { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '❌', ProviderViewer: '❌', CustomerAdmin: '❌', CustomerDeveloper: '❌', CustomerViewer: '❌' },
  '审计日志':          { ProviderOwner: '✅', ProviderAdmin: '👁', ProviderEngineer: '👁', ProviderViewer: '👁', CustomerAdmin: '❌', CustomerDeveloper: '❌', CustomerViewer: '❌' },
  '触发扫描/重扫':     { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '✅', ProviderViewer: '❌', CustomerAdmin: '✅', CustomerDeveloper: '✅', CustomerViewer: '❌' },
  '下载报告':         { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '✅', ProviderViewer: '✅', CustomerAdmin: '✅', CustomerDeveloper: '✅', CustomerViewer: '✅' },
  '成员管理(本客户)':   { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '❌', ProviderViewer: '❌', CustomerAdmin: '✅', CustomerDeveloper: '❌', CustomerViewer: '❌' },
  '客户 webhook':     { ProviderOwner: '✅', ProviderAdmin: '✅', ProviderEngineer: '✅', ProviderViewer: '👁', CustomerAdmin: '✅', CustomerDeveloper: '✅', CustomerViewer: '❌' },
} as const;

const ROLES = ['ProviderOwner', 'ProviderAdmin', 'ProviderEngineer', 'ProviderViewer', 'CustomerAdmin', 'CustomerDeveloper', 'CustomerViewer'] as const;
const RESOURCES = Object.keys(PERMISSION_MATRIX) as Array<keyof typeof PERMISSION_MATRIX>;

const securitySettingsSchema = z.object({
  passwordMinLength: z.number().int().min(8).max(64).default(10),
  passwordRequireUppercase: z.boolean().default(true),
  passwordRequireNumbers: z.boolean().default(true),
  passwordRequireSymbols: z.boolean().default(false),
  maxLoginAttempts: z.number().int().min(3).max(20).default(5),
  lockoutMinutes: z.number().int().min(5).max(1440).default(15),
  sessionTtlMinutes: z.number().int().min(15).max(10080).default(60),
  refreshTokenTtlDays: z.number().int().min(1).max(90).default(7),
  enforceMfaForOwner: z.boolean().default(false),
  ipWhitelist: z.array(z.string()).default([]),
  auditRetentionDays: z.number().int().min(30).max(3650).default(365),
});

export const governancePermsRoutes = new Hono()
  .get('/permissions', async (c) => {
    return c.json({
      roles: ROLES,
      resources: RESOURCES,
      matrix: PERMISSION_MATRIX,
      legend: {
        '✅': '读写',
        '👁': '只读',
        '❌': '无权限',
      },
    });
  })
  .get('/security', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner' && user.role !== 'ProviderAdmin') {
      return c.json({ error: { code: 'forbidden' } }, 403);
    }
    const { rows } = await pool.query(
      `SELECT value FROM meta.app_settings
       WHERE key = $1
       LIMIT 1`,
      [`security:${user.tenantId}`],
    );
    const defaults = securitySettingsSchema.parse({});
    return c.json({ ...defaults, ...(rows[0]?.value ?? {}) });
  })
  .put('/security', async (c) => {
    const user = c.get('user');
    if (user.role !== 'ProviderOwner') {
      return c.json({ error: { code: 'forbidden' } }, 403);
    }
    const body = await c.req.json().catch(() => ({}));
    const parsed = securitySettingsSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', details: parsed.error.flatten() } }, 400);

    await pool.query(
      `INSERT INTO meta.app_settings (key, value, updated_by)
       VALUES ($1, $2::jsonb, $3)
       ON CONFLICT (key) DO UPDATE SET value = $2::jsonb, updated_at = NOW(), updated_by = $3`,
      [`security:${user.tenantId}`, JSON.stringify(parsed.data), user.id],
    );
    await pool.query(
      `INSERT INTO governance.audit_logs
         (tenant_id, actor_user_id, actor_email, event_type, action, metadata)
       VALUES ($1, $2, $3, 'role_change', 'update', $4::jsonb)`,
      [user.tenantId, user.id, user.email, JSON.stringify({ context: 'security_settings_updated', changedKeys: Object.keys(parsed.data) })],
    );
    return c.json(parsed.data);
  });