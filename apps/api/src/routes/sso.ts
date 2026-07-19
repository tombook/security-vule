import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';
import { getSamlPublicKeyPem, getSamlSpMetadata, parseSamlResponse } from '../services/saml';
import { signAccessToken } from '../middleware/auth';

const spEntityId = (tenantId: string) => `https://security-vule.local/sso/sp/${tenantId}`;
const acsUrl = `http://localhost:3000/api/auth/sso/acs`;

const configureSchema = z.object({
  enabled: z.boolean(),
  idpEntityId: z.string(),
  idpSsoUrl: z.string().url(),
  idpPublicKey: z.string().optional(),
  defaultRole: z.string().default('CustomerDeveloper'),
});

export const ssoRoutes = new Hono()
  .get('/config/:tenantId', async (c) => {
    const pg = (c as any).get('pg');
    const tenantId = c.req.param('tenantId');
    const { rows } = await pg.query(
      `SELECT sso_config FROM core.tenants WHERE id = $1`,
      [tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found' } }, 404);
    return c.json(rows[0].sso_config ?? {});
  })
  .put('/config/:tenantId', async (c) => {
    const pg = (c as any).get('pg');
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json().catch(() => null);
    const parsed = configureSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: parsed.error.message } }, 400);

    await pg.query(
      `UPDATE core.tenants SET sso_config = $1::jsonb, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(parsed.data), tenantId],
    );
    return c.json({ ok: true, ssoConfig: parsed.data });
  });

export const ssoPublicRoutes = new Hono()
  .get('/metadata', (c) => {
    const tenantId = c.req.query('tenant_id') ?? 'default';
    const xml = getSamlSpMetadata({
      spEntityId: spEntityId(tenantId),
      acsUrl,
      spName: `security-vule SP for ${tenantId}`,
    });
    return c.text(xml, 200, { 'Content-Type': 'application/xml' });
  })

  .get('/login', (c) => {
    const tenantId = c.req.query('tenant_id') ?? '00000000-0000-0000-0000-000000000001';
    const relayState = c.req.query('relay_state') ?? '/';
    return c.html(`<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="GET" action="/mock-idp/sso">
  <input type="hidden" name="tenant_id" value="${tenantId}" />
  <input type="hidden" name="relay_state" value="${relayState}" />
  <noscript><button>Continue to SSO</button></noscript>
</form>
</body></html>`);
  })

  .post('/acs', async (c) => {
    const body = await c.req.parseBody();
    const samlResponseB64 = (body as any).SAMLResponse as string ?? '';
    const relayState = (body as any).RelayState as string ?? '/';
    if (!samlResponseB64) {
      return c.json({ error: { code: 'bad_request', message: 'missing SAMLResponse' } }, 400);
    }

    const frontendUrl = process.env.FRONTEND_URL ?? 'http://localhost:5173';
    const allKeys = parseAllKeys(samlResponseB64);
    if (!allKeys.idpEntityId) {
      return c.redirect(`${frontendUrl}/sso/error?reason=invalid_response`);
    }
    const audience = allKeys.audience;

    const { rows: tenants } = await pool.query(
      `SELECT id, sso_config FROM core.tenants WHERE sso_config->>'enabled' = 'true'`,
    );
    const tenant = tenants.find((t: any) => audience.includes(t.id));
    if (!tenant) {
      return c.redirect(`${frontendUrl}/sso/error?reason=tenant_not_found&audience=${encodeURIComponent(audience)}`);
    }
    const ssoConfig = tenant.sso_config;
    const idpPublicKey = ssoConfig.idpPublicKey ?? getSamlPublicKeyPem();

    const parsed = parseSamlResponse({
      samlResponseB64,
      expectedAudience: spEntityId(tenant.id),
      idpPublicKeyPem: idpPublicKey,
    });
    if (!parsed.valid) {
      return c.redirect(`${frontendUrl}/sso/error?reason=${encodeURIComponent(parsed.reason ?? 'invalid')}`);
    }

    const email = parsed.email ?? parsed.nameId ?? '';
    if (!email) {
      return c.redirect(`${frontendUrl}/sso/error?reason=no_email`);
    }
    const ssoAttrs = parsed.attributes ?? {};
    const tenantId = ssoAttrs['tenant_id'] ?? tenant.id;
    const customerId = ssoAttrs['customer_id'] || null;
    const role = ssoAttrs['role'] ?? ssoConfig.defaultRole ?? 'CustomerDeveloper';

    const userId = await jitProvision({
      tenantId, email, nameId: parsed.nameId ?? email, role, customerId,
    });

    const access_token = await signAccessToken({
      sub: userId,
      email,
      role,
      tenant_id: tenantId,
      portal: role.startsWith('Provider') ? 'provider' : 'customer',
      customer_id: customerId ?? undefined,
    });

    return c.redirect(`${frontendUrl}/sso/callback#access_token=${access_token}&relay_state=${encodeURIComponent(relayState)}`);
  });

async function jitProvision(opts: {
  tenantId: string;
  email: string;
  nameId: string;
  role: string;
  customerId: string | null;
}): Promise<string> {
  const { tenantId, email, nameId, role, customerId } = opts;
  const { rows: existing } = await pool.query(
    `SELECT id FROM core.users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL LIMIT 1`,
    [tenantId, email],
  );
  if (existing.length > 0) {
    await pool.query(
      `UPDATE core.users SET role = $1::user_role_enum, customer_id = $2, last_login_at = NOW(), updated_at = NOW() WHERE id = $3`,
      [role, customerId, existing[0].id],
    );
    return existing[0].id;
  }
  const { rows: insert } = await pool.query(
    `INSERT INTO core.users (tenant_id, customer_id, portal, email, password_hash, full_name, role, status, last_login_at)
     VALUES ($1, $2, $3, $4, 'sso-no-password', $5, $6::user_role_enum, 'active', NOW())
     RETURNING id`,
    [tenantId, customerId, role.startsWith('Provider') ? 'provider' : 'customer', email, nameId, role],
  );
  return insert[0].id;
}

function parseAllKeys(b64: string): { audience: string; idpEntityId: string } {
  try {
    const xml = Buffer.from(b64, 'base64').toString('utf-8');
    const aud = xml.match(/<saml:Audience>([^<]+)<\/saml:Audience>/)?.[1] ?? '';
    const iss = xml.match(/<saml:Issuer>([^<]+)<\/saml:Issuer>/)?.[1] ?? '';
    return { audience: aud, idpEntityId: iss };
  } catch {
    return { audience: '', idpEntityId: '' };
  }
}
