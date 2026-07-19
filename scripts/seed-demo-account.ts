#!/usr/bin/env bun
/**
 * scripts/seed-demo-account.ts
 *
 * One-shot idempotent seed for the demo login shown on the login screen.
 * Run after `bun run db:migrate` (or any time you want a known-good
 * ProviderOwner account for manual UI smoke-testing).
 *
 *   bun run scripts/seed-demo-account.ts
 *
 * Credentials:
 *   email:    admin@demo.com
 *   password: Admin@123
 *   role:     ProviderOwner (in tenant 'demo-tenant')
 */

import { Pool } from 'pg';
import bcrypt from 'bcryptjs';

const DATABASE_URL = process.env.DATABASE_URL
  ?? 'postgresql://security_vule:dev_password@localhost:5433/security_vule';

const TENANT_ID = '11111111-1111-1111-1111-111111111111';
const USER_ID   = '22222222-2222-2222-2222-222222222222';
const EMAIL     = 'admin@demo.com';
const PASSWORD  = 'Admin@123';

const pool = new Pool({ connectionString: DATABASE_URL });
try {
  const hash = await bcrypt.hash(PASSWORD, 12);

  // Unique on core.users is (tenant_id, email), not email alone.
  await pool.query(
    `INSERT INTO core.tenants (id, name, slug, status)
     VALUES ($1, 'Demo Tenant', 'demo-tenant', 'active')
     ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
    [TENANT_ID],
  );

  await pool.query(
    `INSERT INTO core.users
       (id, tenant_id, customer_id, portal, email, password_hash,
        role, status, failed_login_count, mfa_enabled, locked_until)
     VALUES ($1, $2, NULL, 'provider', $3, $4,
             'ProviderOwner', 'active', 0, false, NULL)
     ON CONFLICT (tenant_id, email) DO UPDATE SET
       password_hash       = EXCLUDED.password_hash,
       role                = 'ProviderOwner',
       portal              = 'provider',
       status              = 'active',
       tenant_id           = EXCLUDED.tenant_id,
       failed_login_count  = 0,
       locked_until        = NULL,
       updated_at          = NOW()`,
    [USER_ID, TENANT_ID, EMAIL, hash],
  );

  const verify = await pool.query(
    `SELECT id, email, role, portal, status, tenant_id
       FROM core.users WHERE tenant_id = $1 AND email = $2`,
    [TENANT_ID, EMAIL],
  );
  console.log('✓ seeded demo account:');
  console.table(verify.rows);
} finally {
  await pool.end();
}