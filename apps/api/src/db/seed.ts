/**
 * 数据库种子脚本
 * 创建 1 个租户 + 1 个 admin 用户 + 3 个演示客户
 * 运行: bun run src/db/seed.ts
 */
import { pool } from './client';
import bcrypt from 'bcryptjs';

const TENANT_ID = '00000000-0000-0000-0000-000000000001';
const ADMIN_EMAIL = 'admin@demo.com';
const ADMIN_PASSWORD = 'Admin@123';

const customers = [
  { id: '00000000-0000-0000-0000-000000000010', name: '某科技公司', slug: 'tech-corp', status: 'active' },
  { id: '00000000-0000-0000-0000-000000000011', name: '金融客户', slug: 'finance-corp', status: 'active' },
  { id: '00000000-0000-0000-0000-000000000012', name: '制造客户', slug: 'mfg-corp', status: 'suspended' },
];

async function main() {
  const client = await pool.connect();
  try {
    console.log('[seed] start');

    await client.query(
      `INSERT INTO core.tenants (id, name, slug, plan, status)
       VALUES ($1, $2, $3, 'pro', 'active')
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = 'active'`,
      [TENANT_ID, '演示安全服务商', 'demo'],
    );
    console.log('[seed] tenant upserted');

    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await client.query(
      `INSERT INTO core.users (id, tenant_id, portal, email, password_hash, full_name, role, status, last_login_at)
       VALUES ($1, $2, 'provider', $3, $4, '演示管理员', 'ProviderOwner', 'active', NOW())
       ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash, status = 'active'`,
      [crypto.randomUUID(), TENANT_ID, ADMIN_EMAIL, passwordHash],
    );
    console.log(`[seed] admin user upserted: ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);

    for (const c of customers) {
      await client.query(
        `INSERT INTO core.customers (id, tenant_id, name, slug, status, contact_email)
         VALUES ($1, $2, $3, $4, $5::customer_status_enum, $6)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status`,
        [c.id, TENANT_ID, c.name, c.slug, c.status, `contact@${c.slug}.com`],
      );
    }
    console.log(`[seed] ${customers.length} customers upserted`);

    console.log('[seed] done ✓');
  } catch (err) {
    console.error('[seed] failed:', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

main();
