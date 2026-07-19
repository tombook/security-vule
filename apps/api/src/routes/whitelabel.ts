import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';

const DEFAULT_THEME = {
  companyName: 'security-vule',
  logoUrl: '',
  primaryColor: '#4F46E5',
  faviconUrl: '',
  loginBackgroundUrl: '',
  customDomain: '',
  emailFromName: 'security-vule',
  emailFromAddress: 'noreply@security-vule.local',
  supportEmail: 'support@security-vule.local',
  privacyPolicyUrl: '',
  termsOfServiceUrl: '',
};

const whitelabelSchema = z.object({
  companyName: z.string().min(1).max(100).optional(),
  logoUrl: z.string().url().max(500).optional().or(z.literal('')),
  primaryColor: z.string().regex(/^#[0-9A-Fa-f]{6}$/).optional(),
  faviconUrl: z.string().url().max(500).optional().or(z.literal('')),
  loginBackgroundUrl: z.string().url().max(500).optional().or(z.literal('')),
  customDomain: z.string().max(100).optional(),
  emailFromName: z.string().max(100).optional(),
  emailFromAddress: z.string().email().optional(),
  supportEmail: z.string().email().optional(),
  privacyPolicyUrl: z.string().url().max(500).optional().or(z.literal('')),
  termsOfServiceUrl: z.string().url().max(500).optional().or(z.literal('')),
});

export const whitelabelRoutes = new Hono()
  .get('/', async (c) => {
    const pg = (c as any).get('pg');
    const { rows } = await pg.query(
      `SELECT white_label FROM core.tenants WHERE id = $1`,
      [c.get('user').tenantId],
    );
    const tenantTheme = rows[0]?.white_label ?? {};
    return c.json({ ...DEFAULT_THEME, ...tenantTheme });
  })

  .put('/', async (c) => {
    const pg = (c as any).get('pg');
    const body = await c.req.json().catch(() => null);
    const parsed = whitelabelSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: parsed.error.message } }, 400);

    const existing = await pg.query(
      `SELECT white_label FROM core.tenants WHERE id = $1`,
      [c.get('user').tenantId],
    );
    const merged = { ...(existing.rows[0]?.white_label ?? {}), ...parsed.data };
    const cleaned = Object.fromEntries(
      Object.entries(merged).filter(([_, v]) => v !== null && v !== undefined),
    );

    await pg.query(
      `UPDATE core.tenants SET white_label = $1::jsonb, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(cleaned), c.get('user').tenantId],
    );
    return c.json({ ...DEFAULT_THEME, ...cleaned });
  })

  .get('/preview', async (c) => {
    const pg = (c as any).get('pg');
    const { rows } = await pg.query(
      `SELECT white_label, name FROM core.tenants WHERE id = $1`,
      [c.get('user').tenantId],
    );
    const theme = rows[0]?.white_label ?? {};
    return c.json({
      ...DEFAULT_THEME,
      ...theme,
      companyName: theme.companyName ?? rows[0]?.name ?? DEFAULT_THEME.companyName,
      preview: {
        primaryColor: theme.primaryColor ?? DEFAULT_THEME.primaryColor,
        logoUrl: theme.logoUrl ?? '',
        supportsCustomDomain: Boolean(theme.customDomain),
      },
    });
  });
