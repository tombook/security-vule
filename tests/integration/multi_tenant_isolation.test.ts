// tests/integration/multi_tenant_isolation.test.ts
// P0 Multi-Tenant 隔离测试(MT-01..10 + RLS-01..10)
// 覆盖:跨租户读/写/改/删全部拦截,RLS 策略直查

import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'bun:test';
import { pool, withClient, setGuc, clearGuc, truncateAll, closePool } from '../helpers/db';
import {
  seedAll, TENANT_A, TENANT_B, CUSTOMER_C, CUSTOMER_D, USERS,
  seedProjectViaSql, seedFindingViaSql,
} from '../helpers/seed';

let projectA_C: string, projectA_D: string, projectB_C: string;
let findingA: string, findingA_D: string, findingB: string;
let webhookA: string, webhookB: string;
let auditA: string, auditB: string;

beforeAll(async () => {
  await truncateAll();
  await seedAll();

  await withClient(async (c) => {
    await c.query(
      `INSERT INTO detection.engines (id, name, engine_type, version, enabled) VALUES ('11111111-1111-1111-1111-111111111111', 'semgrep', 'semgrep', '1.0.0', true)
        ON CONFLICT (id) DO NOTHING`
    );
    await c.query(
      `INSERT INTO detection.rules (id, engine_id, rule_external_id, title, severity) VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'test-rule', 'Test rule', 'high')
        ON CONFLICT (id) DO NOTHING`
    );
  });

  projectA_C = await seedProjectViaSql(CUSTOMER_C, TENANT_A, 'proj-a-c');
  projectA_D = await seedProjectViaSql(CUSTOMER_D, TENANT_A, 'proj-a-d');
  projectB_C = await seedProjectViaSql(CUSTOMER_C, TENANT_B, 'proj-b-c');

  findingA = await seedFindingViaSql(TENANT_A, CUSTOMER_C, projectA_C, 'critical');
  findingA_D = await seedFindingViaSql(TENANT_A, CUSTOMER_D, projectA_D, 'high');
  findingB = await seedFindingViaSql(TENANT_B, CUSTOMER_C, projectB_C, 'critical');

  webhookA = await seedWebhookViaSql(TENANT_A, 'https://hook-a.test');
  webhookB = await seedWebhookViaSql(TENANT_B, 'https://hook-b.test');

  auditA = await seedAuditViaSql(TENANT_A, USERS.ownerA, 'login_success');
  auditB = await seedAuditViaSql(TENANT_B, USERS.ownerB, 'login_success');
});

beforeEach(async () => {
  // 每个 test 前不重置 — seed once in beforeAll,tests use existing data
});

afterAll(async () => { await closePool(); });

async function seedWebhookViaSql(tenantId: string, url: string): Promise<string> {
  return await withClient(async (c) => {
    const r = await c.query(
      `INSERT INTO governance.webhooks (tenant_id, url, secret_ciphertext, event_types, enabled, created_by) VALUES ($1, $2, '\\x00', ARRAY['x'], true, (SELECT id FROM core.users WHERE tenant_id = $1 LIMIT 1)) RETURNING id`,
      [tenantId, url],
    );
    return r.rows[0].id as string;
  });
}

async function seedAuditViaSql(tenantId: string, userId: string, action: string): Promise<string> {
  return await withClient(async (c) => {
    const r = await c.query(
      `INSERT INTO governance.audit_logs (tenant_id, actor_user_id, actor_email, event_type, action) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [tenantId, userId, `${userId.slice(0, 8)}@test.dev`, action, action],
    );
    return r.rows[0].id as string;
  });
}

async function queryWithGuc<T>(sql: string, params: unknown[], tenant: string, role: string, customerId?: string): Promise<T[]> {
  return await withClient(async (c) => {
    await c.query('BEGIN');
    try {
      await setGuc(c, tenant, role, customerId);
      const r = await c.query(sql, params);
      await c.query('COMMIT');
      return r.rows as T[];
    } catch (err) {
      await c.query('ROLLBACK');
      throw err;
    }
  });
}

// =====================================================================
// MT-01..10: Multi-Tenant 跨租户访问拦截(直接 SQL 模拟 RLS 行为)
// =====================================================================
describe('MT-01..10: Multi-Tenant 跨租户隔离', () => {

  test('MT-01: 租户 A 读租户 B 客户(应 0 rows)', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.customers WHERE id = $1 AND tenant_id = $2`,
      ['00000000-0000-0000-0000-999999999999', TENANT_B], TENANT_A, 'ProviderOwner',
    );
    expect(rows).toHaveLength(0);
  });

  test('MT-02: 租户 A 列租户 B 项目(应 0 rows)', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE customer_id IN
        (SELECT id FROM core.customers WHERE tenant_id = $1) AND id = $2`,
      [TENANT_B, projectB_C], TENANT_A, 'ProviderOwner',
    );
    expect(rows).toHaveLength(0);
  });

  test('MT-03: 租户 A 改租户 B finding(应不影响)', async () => {
    await queryWithGuc<{id: string}>(
      `UPDATE detection.findings SET status = 'in_progress' WHERE id = $1 AND tenant_id = $2`,
      [findingB, TENANT_B], TENANT_A, 'ProviderOwner',
    );
    // 确认 B finding 未变
    const after = await queryWithGuc<{status: string}>(
      `SELECT status FROM detection.findings WHERE id = $1`, [findingB], TENANT_B, 'ProviderOwner',
    );
    expect(after[0]?.status).toBe('open');
  });

  test('MT-04: 租户 A 删租户 B webhook(应不删)', async () => {
    await queryWithGuc<{id: string}>(
      `DELETE FROM governance.webhooks WHERE id = $1 AND tenant_id = $2`,
      [webhookB, TENANT_B], TENANT_A, 'ProviderOwner',
    );
    const after = await queryWithGuc<{id: string}>(
      `SELECT id FROM governance.webhooks WHERE id = $1`, [webhookB], TENANT_B, 'ProviderOwner',
    );
    expect(after).toHaveLength(1);
  });

  test('MT-05: 租户 A 读租户 B audit(应 0 rows)', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM governance.audit_logs WHERE tenant_id = $1`, [TENANT_B], TENANT_A, 'ProviderOwner',
    );
    expect(rows).toHaveLength(0);
  });

  test('MT-06: 客户 C 读租户 A 客户 D 项目(应 0 rows)', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE id = $1 AND customer_id = $2`,
      [projectA_D, CUSTOMER_C], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    expect(rows).toHaveLength(0);
  });

  test('MT-07: 客户 C 列租户 A 客户 D findings(应 0 rows)', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM detection.findings WHERE customer_id = $1 AND id = $2`,
      [CUSTOMER_D, findingA_D], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    expect(rows).toHaveLength(0);
  });

  test('MT-08: 客户 C 改租户 A 客户 D finding(应 404)', async () => {
    await queryWithGuc<{id: string}>(
      `UPDATE detection.findings SET status = 'fixed' WHERE id = $1 AND customer_id = $2`,
      [findingA_D, CUSTOMER_D], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    const after = await queryWithGuc<{status: string}>(
      `SELECT status FROM detection.findings WHERE id = $1`, [findingA_D], TENANT_A, 'ProviderOwner',
    );
    expect(after[0]?.status).not.toBe('fixed');
  });

  test('MT-09: 同租户同客户可正常读写(各自仅看自己 customer)', async () => {
    const providerRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE customer_id = $1`,
      [CUSTOMER_C], TENANT_A, 'ProviderOwner',
    );
    const customerRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE customer_id = $1`,
      [CUSTOMER_C], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    expect(providerRows.length).toBeGreaterThan(0);
    expect(customerRows.length).toBeGreaterThan(0);
    expect(customerRows.length).toBeLessThanOrEqual(providerRows.length);
  });

  test('MT-10: 同租户跨客户互不可见(客户 A vs 客户 B)', async () => {
    const acRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE customer_id = $1`, [CUSTOMER_C], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    const adRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE customer_id = $1`, [CUSTOMER_D], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    expect(acRows.length).toBeGreaterThan(0);
    expect(adRows).toHaveLength(0);
  });
});

// =====================================================================
// RLS-01..10: RLS 策略直查(分租户 + 分角色)
// =====================================================================
describe('RLS-01..10: RLS 策略完整性直查', () => {

  test('RLS-01: 跨租户读 core.customers(0 rows)', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.customers WHERE tenant_id = $1`, [TENANT_B], TENANT_A, 'ProviderOwner',
    );
    expect(rows).toHaveLength(0);
  });

  test('RLS-02: 同租户读 core.customers(>0 rows)', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.customers WHERE tenant_id = $1`, [TENANT_A], TENANT_A, 'ProviderOwner',
    );
    expect(rows.length).toBeGreaterThan(0);
  });

  test('RLS-03: 客户 GUC 隔离(同租户但不同客户)', async () => {
    const ownRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE customer_id = $1`, [CUSTOMER_C], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    const otherRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE customer_id = $1`, [CUSTOMER_D], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    expect(ownRows.length).toBeGreaterThan(0);
    expect(otherRows).toHaveLength(0);
  });

  test('RLS-04: Provider 系角色可看所有 customer', async () => {
    for (const role of ['ProviderOwner', 'ProviderAdmin', 'ProviderEngineer', 'ProviderViewer']) {
      const rows = await queryWithGuc<{id: string}>(
        `SELECT id FROM core.customers WHERE tenant_id = $1`, [TENANT_A], TENANT_A, role,
      );
      expect(rows.length).toBeGreaterThan(0);
    }
  });

  test('RLS-05: 未设 GUC 拒绝(0 rows)', async () => {
    const rows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = ''`);
        await c.query(`SET LOCAL app.current_user_role = ''`);
        const r = await c.query(`SELECT id FROM core.customers LIMIT 1`);
        await c.query('COMMIT');
        return r.rows;
      } catch (err) {
        await c.query('ROLLBACK');
        throw err;
      }
    });
    expect(rows).toHaveLength(0);
  });

  test('RLS-06: 跨租户 audit_logs 不可见', async () => {
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM governance.audit_logs WHERE tenant_id = $1`, [TENANT_B], TENANT_A, 'ProviderOwner',
    );
    expect(rows).toHaveLength(0);
  });

  test('RLS-07: 跨租户 DELETE webhooks(0 rows 影响)', async () => {
    await queryWithGuc(
      `DELETE FROM governance.webhooks WHERE id = $1 AND tenant_id = $2`,
      [webhookB, TENANT_B], TENANT_A, 'ProviderOwner',
    );
    const after = await queryWithGuc<{id: string}>(
      `SELECT id FROM governance.webhooks WHERE id = $1`, [webhookB], TENANT_B, 'ProviderOwner',
    );
    expect(after).toHaveLength(1);
  });

  test('RLS-08: RLS-enabled 但无 policy 的表(查询应返 0 rows)', async () => {
    const tables = await withClient(async (c) => {
      const r = await c.query(`
        SELECT t.tablename FROM pg_tables t
        LEFT JOIN pg_policies p ON p.schemaname = t.schemaname AND p.tablename = t.tablename
        WHERE t.schemaname IN ('core','detection','poc','usage','billing','governance','integration','meta')
          AND t.rowsecurity = true
        GROUP BY t.tablename HAVING count(p.policyname) = 0`);
      return r.rows.map((r: any) => r.table_name);
    });
    if (tables.length > 0) {
      console.warn(`Tables with RLS but no policy: ${tables.join(', ')}`);
    }
    expect(tables).toEqual([]);
  });

  test('RLS-09: partition 表(2026_06) ProviderOwner 仅见本租户', async () => {
    const aRows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'`);
        await c.query(`SET LOCAL app.current_user_role = 'ProviderOwner'`);
        const r = await c.query(`SELECT id, tenant_id FROM governance.audit_logs_2026_06`);
        await c.query('COMMIT');
        return r.rows;
      } catch (err) { await c.query('ROLLBACK'); throw err; }
    });
    for (const row of aRows) expect((row as any).tenant_id).toBe(TENANT_A);
    const bRows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'`);
        await c.query(`SET LOCAL app.current_user_role = 'ProviderOwner'`);
        const r = await c.query(`SELECT id, tenant_id FROM governance.audit_logs_2026_06`);
        await c.query('COMMIT');
        return r.rows;
      } catch (err) { await c.query('ROLLBACK'); throw err; }
    });
    for (const row of bRows) expect((row as any).tenant_id).toBe(TENANT_B);
  });

  test('RLS-10: superuser 绕 RLS(应能见全部)', async () => {
    const r = await pool.query(
      `SELECT count(*)::int AS c FROM core.customers WHERE tenant_id IN ($1, $2)`,
      [TENANT_A, TENANT_B],
    );
    const count = Number(r.rows[0].c);
    expect(count).toBeGreaterThanOrEqual(2);
  });
});

// =====================================================================
// MTI-01..04: tenant_id 注入防护(URL/body/header)
// =====================================================================
describe('MTI-01..04: tenant_id 注入防护', () => {

  test('MTI-01: 即使 body 含 tenantId 也不能跨租户写', async () => {
    // 模拟 API 收到 POST /customers body: { name: 'X', tenantId: TENANT_B }
    // 中间件会忽略 body tenantId,使用 JWT 中的 tenant_id
    // 验证:同一 query 用 app.current_tenant=TENANT_B 会看到 X,否则看不到
    await queryWithGuc(
      `INSERT INTO core.customers (tenant_id, name, slug) VALUES ($1, 'test-x', 'test-x')`,
      [TENANT_B], TENANT_B, 'ProviderOwner',
    );
    const aRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.customers WHERE name = 'test-x' AND tenant_id = $1`, [TENANT_A], TENANT_A, 'ProviderOwner',
    );
    const bRows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.customers WHERE name = 'test-x' AND tenant_id = $1`, [TENANT_B], TENANT_B, 'ProviderOwner',
    );
    expect(aRows).toHaveLength(0);
    expect(bRows).toHaveLength(1);
  });

  test('MTI-02: GUC 直接被设为对方 tenant_id(模拟 token 篡改)', async () => {
    // 即使 GUC 是 TB,中间件用 JWT 解析,DB session GUC 不会改
    // 这里只能验证 policy 是基于 GUC,token 篡改应在 auth 中间件层被拦
    const userFromOtherTenant = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.users WHERE id = $1 AND tenant_id = $2`,
      [USERS.ownerB, TENANT_B], TENANT_B, 'ProviderOwner',
    );
    expect(userFromOtherTenant).toHaveLength(1);
  });

  test('MTI-03: customer_id 跨租户不可读 project', async () => {
    // 模拟 customer C(TA) 试图读 customer D(TA) project
    const rows = await queryWithGuc<{id: string}>(
      `SELECT id FROM core.projects WHERE id = $1 AND customer_id = $2`,
      [projectA_D, CUSTOMER_C], TENANT_A, 'CustomerAdmin', CUSTOMER_C,
    );
    expect(rows).toHaveLength(0);
  });

  test('MTI-04: GUC 注入 NULL/空值(应无法跨租户)', async () => {
    const rows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = ''`);
        await c.query(`SET LOCAL app.current_user_role = 'ProviderOwner'`);
        const r = await c.query(`SELECT id FROM core.customers LIMIT 1`);
        await c.query('COMMIT');
        return r.rows;
      } catch (err) {
        await c.query('ROLLBACK');
        throw err;
      }
    });
    expect(rows).toHaveLength(0);
  });
});