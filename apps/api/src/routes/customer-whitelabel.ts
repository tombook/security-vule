import { Hono } from 'hono';
import { pool } from '../db/client';

const DEFAULT_THEME = {
  companyName: 'security-vule',
  logoUrl: '',
  primaryColor: '#4F46E5',
  faviconUrl: '',
  loginBackgroundUrl: '',
  supportEmail: 'support@security-vule.local',
  privacyPolicyUrl: '',
  termsOfServiceUrl: '',
};

export const customerWhitelabelRoutes = new Hono()
  .get('/', async (c) => {
    const user = c.get('user');
    if (user.portal !== 'customer' || !user.customerId) {
      return c.json({ error: { code: 'forbidden', message: 'Customer portal required' } }, 403);
    }

    const { rows } = await pool.query(
      `SELECT
         COALESCE(c.white_label, '{}'::jsonb) AS customer_theme,
         COALESCE(t.white_label, '{}'::jsonb) AS tenant_theme,
         c.name AS customer_name,
         t.name AS tenant_name
       FROM core.customers c
       JOIN core.tenants t ON t.id = c.tenant_id
       WHERE c.id = $1`,
      [user.customerId],
    );
    if (rows.length === 0) return c.json({ ...DEFAULT_THEME });

    const customerTheme = rows[0].customer_theme ?? {};
    const tenantTheme = rows[0].tenant_theme ?? {};
    const merged = {
      ...DEFAULT_THEME,
      ...tenantTheme,
      ...customerTheme,
    };
    if (customerTheme.companyName ?? tenantTheme.companyName ?? rows[0].customer_name) {
      merged.companyName = customerTheme.companyName ?? tenantTheme.companyName ?? rows[0].customer_name;
    }
    return c.json(merged);
  });
