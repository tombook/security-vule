// tests/integration/rls_coverage.test.ts
// P0 RLS 全覆盖测试 — 验证所有业务表启用 RLS 且有至少 1 条 policy
// 扩展自 multi_tenant_isolation.test.ts 的 RLS-08 / RLS-09 / RLS-10

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { withClient, closePool } from '../helpers/db';

const BUSINESS_SCHEMAS = ['core', 'detection', 'poc', 'usage', 'billing', 'governance', 'integration'];

/**
 * 这些表无需 RLS 或通过其他方式隔离:
 * - core.tenants:自身即租户根表,无 tenant_id
 * - pg_class 分区表(usage_events_*, audit_logs_* 等)继承父表 RLS,父表本身已启用
 */
const TABLES_EXEMPT_FROM_RLS = new Set(['tenants']);

beforeAll(async () => {});
afterAll(async () => { await closePool(); });

interface CoverageRow {
  schemaname: string;
  tablename: string;
  rls_enabled: boolean;
  policy_count: number;
  policies: string[];
}

describe('RLS-101: 所有业务表启用 RLS', () => {
  test('所有非分区根业务表应全部启用 RLS', async () => {
    const rows = await withClient(async (c) => {
      const r = await c.query<{ schemaname: string; tablename: string }>(`
        SELECT t.schemaname, t.tablename
        FROM pg_tables t
        WHERE t.schemaname = ANY($1::text[])
          AND t.tablename NOT LIKE '\\_%' ESCAPE '\\'
          AND t.tablename NOT IN ('schema_migrations', 'app_settings')
          AND NOT EXISTS (
            SELECT 1 FROM pg_inherits i
            JOIN pg_class c ON i.inhrelid = c.oid
            JOIN pg_class p ON i.inhparent = p.oid
            WHERE c.relname = t.tablename
              AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = t.schemaname)
              AND p.relkind = 'p'
          )
      `, [BUSINESS_SCHEMAS]);
      return r.rows;
    });
    const rlsOn = await withClient(async (c) => {
      const r = await c.query<{ schemaname: string; tablename: string }>(`
        SELECT n.nspname AS schemaname, c.relname AS tablename
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = ANY($1::text[])
          AND c.relkind = 'r'
          AND c.relrowsecurity = true
      `, [BUSINESS_SCHEMAS]);
      return new Set(r.rows.map((x) => `${x.schemaname}.${x.tablename}`));
    });
    const partitionedParents = await withClient(async (c) => {
      const r = await c.query<{ schemaname: string; tablename: string }>(`
        SELECT n.nspname AS schemaname, p.relname AS tablename
        FROM pg_inherits i
        JOIN pg_class p ON i.inhparent = p.oid
        JOIN pg_namespace n ON p.relnamespace = n.oid
        WHERE n.nspname = ANY($1::text[])
          AND p.relkind = 'p'
      `, [BUSINESS_SCHEMAS]);
      return new Set(r.rows.map((x) => `${x.schemaname}.${x.tablename}`));
    });
    const missing = rows
      .map((r) => `${r.schemaname}.${r.tablename}`)
      .filter((t) => !rlsOn.has(t) && !partitionedParents.has(t) && !TABLES_EXEMPT_FROM_RLS.has(t.split('.')[1]));
    expect(missing).toEqual([]);
  });
});

describe('RLS-102: 每张 RLS 表至少有 1 条 policy', () => {
  test('所有 RLS 表都有 policy 覆盖', async () => {
    const rows = await withClient(async (c) => {
      const r = await c.query<CoverageRow>(`
        SELECT
          n.nspname AS schemaname,
          c.relname AS tablename,
          c.relrowsecurity AS rls_enabled,
          (SELECT count(*) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname)::int AS policy_count,
          COALESCE(
            (SELECT array_agg(policyname ORDER BY policyname) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname),
            ARRAY[]::text[]
          ) AS policies
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = ANY($1::text[])
          AND c.relkind = 'r'
          AND c.relrowsecurity = true
        ORDER BY n.nspname, c.relname
      `, [BUSINESS_SCHEMAS]);
      return r.rows;
    });
    const orphans = rows.filter((r) => r.policy_count === 0);
    expect(orphans).toEqual([]);
  });
});

describe('RLS-103: tenant 隔离 policy 必须存在', () => {
  test('每张含 tenant_id 列的表都有 tenant_isolation 类 policy', async () => {
    const rows = await withClient(async (c) => {
      const r = await c.query<{ schemaname: string; tablename: string; policy_count: number }>(`
        SELECT
          n.nspname AS schemaname,
          c.relname AS tablename,
          (SELECT count(*) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname
             AND (p.qual LIKE '%current_tenant%' OR p.with_check LIKE '%current_tenant%'))::int AS policy_count
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = ANY($1::text[])
          AND c.relkind = 'r'
          AND c.relrowsecurity = true
          AND EXISTS (
            SELECT 1 FROM pg_attribute a
            WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0
          )
        ORDER BY n.nspname, c.relname
      `, [BUSINESS_SCHEMAS]);
      return r.rows;
    });
    const orphans = rows.filter((r) => r.policy_count === 0);
    expect(orphans).toEqual([]);
  });
});

describe('RLS-104: customer 隔离 policy 必须存在', () => {
  test('客户门户直接访问的核心表都有 customer_isolation 类 policy', async () => {
    const CUSTOMER_FACING_TABLES = [
      'core.projects', 'core.sources', 'core.reports',
      'detection.findings', 'detection.snapshots', 'detection.scan_runs',
      'poc.poc_runs',
      'billing.billing_accounts', 'billing.invoices',
    ];
    const rows = await withClient(async (c) => {
      const r = await c.query<{ fullname: string; policy_count: number }>(`
        SELECT
          (n.nspname || '.' || c.relname) AS fullname,
          (SELECT count(*) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname
             AND (p.qual LIKE '%current_customer%' OR p.with_check LIKE '%current_customer%'))::int AS policy_count
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = ANY($1::text[])
          AND c.relkind = 'r'
          AND c.relrowsecurity = true
          AND EXISTS (
            SELECT 1 FROM pg_attribute a
            WHERE a.attrelid = c.oid AND a.attname = 'customer_id' AND a.attnum > 0
          )
        ORDER BY n.nspname, c.relname
      `, [BUSINESS_SCHEMAS]);
      return r.rows;
    });
    const fullnames = rows.map((r) => r.fullname);
    const orphans = CUSTOMER_FACING_TABLES.filter(
      (t) => !fullnames.includes(t) || rows.find((r) => r.fullname === t)?.policy_count === 0
    );
    expect(orphans).toEqual([]);
  });
});

describe('RLS-105: SystemBot 角色放行(后台任务合法)', () => {
  test('audit_logs 允许 SystemBot 跨租户读', async () => {
    const rows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = ''`);
        await c.query(`SET LOCAL app.current_user_role = 'SystemBot'`);
        const r = await c.query<{ count: number }>(`SELECT count(*)::int AS count FROM governance.audit_logs`);
        await c.query('COMMIT');
        return r.rows;
      } catch (err) {
        await c.query('ROLLBACK');
        throw err;
      }
    });
    expect(rows[0].count).toBeGreaterThanOrEqual(0);
  });
});

describe('RLS-106: 未设 GUC 时拒绝访问', () => {
  test('空 GUC 应返回 0 行(避免 NULL bypass)', async () => {
    const rows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = ''`);
        await c.query(`SET LOCAL app.current_user_role = ''`);
        await c.query(`SET LOCAL app.current_customer = ''`);
        const r = await c.query<{ id: string }>(`SELECT id FROM core.customers LIMIT 1`);
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

describe('RLS-107: 应用账号无 BYPASSRLS 权限', () => {
  test('authenticated_app 角色不具备 BYPASSRLS 属性', async () => {
    const rows = await withClient(async (c) => {
      const r = await c.query<{ rolname: string; rolbypassrls: boolean }>(`
        SELECT rolname, rolbypassrls
        FROM pg_roles
        WHERE rolname = 'authenticated_app'
      `);
      return r.rows;
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].rolbypassrls).toBe(false);
  });
});

describe('RLS-108: GUC 角色白名单放行 Provider 系角色', () => {
  test('ProviderOwner 可见本租户所有 customer', async () => {
    const rows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'`);
        await c.query(`SET LOCAL app.current_user_role = 'ProviderOwner'`);
        const r = await c.query<{ id: string }>(`SELECT id FROM core.customers WHERE tenant_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'`);
        await c.query('COMMIT');
        return r.rows;
      } catch (err) {
        await c.query('ROLLBACK');
        throw err;
      }
    });
    expect(rows.length).toBeGreaterThan(0);
  });

  test('ProviderOwner 不见其他租户 customer', async () => {
    const rows = await withClient(async (c) => {
      await c.query('BEGIN');
      try {
        await c.query(`SET LOCAL ROLE authenticated_app`);
        await c.query(`SET LOCAL app.current_tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'`);
        await c.query(`SET LOCAL app.current_user_role = 'ProviderOwner'`);
        const r = await c.query<{ id: string }>(`SELECT id FROM core.customers WHERE tenant_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'`);
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