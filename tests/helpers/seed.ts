// tests/helpers/seed.ts
// 多租户多角色测试 fixtures

import { withClient } from './db';

export const TENANT_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
export const TENANT_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
export const CUSTOMER_C = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
export const CUSTOMER_D = 'dddddddd-dddd-dddd-dddd-dddddddddddd';

export const USERS = {
  ownerA:    '00000000-0000-0000-0000-00000000a001',
  adminA:    '00000000-0000-0000-0000-00000000a002',
  engineerA: '00000000-0000-0000-0000-00000000a003',
  viewerA:   '00000000-0000-0000-0000-00000000a004',
  adminC:    '00000000-0000-0000-0000-00000000b001',
  developerC: '00000000-0000-0000-0000-00000000b002',
  viewerC:   '00000000-0000-0000-0000-00000000b003',
  ownerB:    '00000000-0000-0000-0000-00000000c001',
};

export type Role = 'ProviderOwner' | 'ProviderAdmin' | 'ProviderEngineer' | 'ProviderViewer'
  | 'CustomerAdmin' | 'CustomerDeveloper' | 'CustomerViewer';

const TEST_PASSWORD = 'TestPass123';
const TEST_PASSWORD_HASH = '$2a$12$Ffwy6h3X9tpM2y9It9NoueXQhrwBUqIoR8XkggQiJdWa/.kU6UrSe';

export const SEED_PASSWORD = TEST_PASSWORD;

export interface SeededUser {
  id: string;
  tenantId: string;
  customerId?: string;
  email: string;
  role: Role;
}

export async function seedAll(): Promise<void> {
  await withClient(async (c) => {
    await c.query('BEGIN');
    try {
      await c.query(`INSERT INTO core.tenants (id, name, slug, plan, status) VALUES
        ($1, 'Provider A', 'provider-a', 'enterprise', 'active'),
        ($2, 'Provider B', 'provider-b', 'pro', 'active')`,
        [TENANT_A, TENANT_B]);

      await c.query(`INSERT INTO core.users (id, tenant_id, portal, email, password_hash, role, status) VALUES
        ($1, $2, 'provider', 'owner-a@test.dev', $3, 'ProviderOwner', 'active'),
        ($4, $2, 'provider', 'admin-a@test.dev', $3, 'ProviderAdmin', 'active'),
        ($5, $2, 'provider', 'eng-a@test.dev',   $3, 'ProviderEngineer', 'active'),
        ($6, $2, 'provider', 'view-a@test.dev',  $3, 'ProviderViewer', 'active'),
        ($7, $8, 'provider', 'owner-b@test.dev', $3, 'ProviderOwner', 'active')`,
        [USERS.ownerA, TENANT_A, TEST_PASSWORD_HASH, USERS.adminA, USERS.engineerA, USERS.viewerA, USERS.ownerB, TENANT_B]);

      await c.query(`INSERT INTO core.customers (id, tenant_id, name, slug) VALUES
        ($1, $2, 'Customer C', 'customer-c'),
        ($3, $2, 'Customer D', 'customer-d')`,
        [CUSTOMER_C, TENANT_A, CUSTOMER_D]);

      await c.query(`INSERT INTO core.users (id, tenant_id, customer_id, portal, email, password_hash, role, status) VALUES
        ($1, $2, $3, 'customer', 'admin-c@test.dev',  $4, 'CustomerAdmin', 'active'),
        ($5, $2, $3, 'customer', 'dev-c@test.dev',    $4, 'CustomerDeveloper', 'active'),
        ($6, $2, $3, 'customer', 'view-c@test.dev',   $4, 'CustomerViewer', 'active')`,
        [USERS.adminC, TENANT_A, CUSTOMER_C, TEST_PASSWORD_HASH, USERS.developerC, USERS.viewerC]);

      await c.query('COMMIT');
    } catch (err) {
      await c.query('ROLLBACK');
      throw err;
    }
  });
}

export async function seedProject(customerId: string, name: string = 'test-proj'): Promise<string> {
  return await withClient(async (c) => {
    const r = await c.query(
      `INSERT INTO core.projects (tenant_id, customer_id, name, slug, status) VALUES
       ($1, $2, $3, $4, 'active') RETURNING id`,
      [customerId === CUSTOMER_C ? TENANT_A : TENANT_B, customerId, name, name.toLowerCase()],
    );
    return r.rows[0].id as string;
  });
}

export async function seedFinding(tenantId: string, customerId: string, projectId: string, severity = 'high', status = 'open'): Promise<string> {
  return await withClient(async (c) => {
    const r = await c.query(
      `INSERT INTO detection.findings
        (tenant_id, customer_id, project_id, scan_run_id, snapshot_id, rule_id,
         fingerprint, severity, status, title, file_path, start_line, end_line)
       SELECT $1, $2, $3,
        (SELECT id FROM detection.scan_runs WHERE project_id = $3 LIMIT 1),
        (SELECT id FROM detection.snapshots WHERE project_id = $3 LIMIT 1),
        (SELECT id FROM detection.rules WHERE default_enabled = true LIMIT 1),
        $4, $5::severity_enum, $6::finding_status_enum, 'Test finding', '/src/test.ts', 1, 5
       RETURNING id`,
      [tenantId, customerId, projectId,
       `fp-${tenantId.slice(0, 8)}-${customerId.slice(0, 8)}-${Math.random().toString(36).slice(2, 10)}`,
       severity, status],
    );
    return r.rows[0].id as string;
  });
}

export async function seedFindingForProject(tenantId: string, customerId: string, projectId: string, scanRunId: string, snapshotId: string, opts: {
  severity?: string; status?: string; title?: string; fingerprint?: string;
} = {}): Promise<string> {
  return await withClient(async (c) => {
    const r = await c.query(
      `INSERT INTO detection.findings
        (tenant_id, customer_id, project_id, scan_run_id, snapshot_id, rule_id,
         fingerprint, severity, status, title, file_path, start_line, end_line)
       SELECT $1, $2, $3, $4, $5,
        (SELECT id FROM detection.rules WHERE default_enabled = true LIMIT 1),
        $6, $7::severity_enum, $8::finding_status_enum, $9, '/src/test.ts', 1, 5
       RETURNING id`,
      [tenantId, customerId, projectId, scanRunId, snapshotId,
       opts.fingerprint ?? `fp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
       opts.severity ?? 'high', opts.status ?? 'open', opts.title ?? 'Test finding'],
    );
    return r.rows[0].id as string;
  });
}

/**
 * 直接 SQL 注入项目(绕过 API);返回新项目 id。
 * 测试场景需要"已知存在的项目 id"用于 body 占位符。
 */
export async function seedProjectViaSql(customerId: string, tenantId: string, name: string): Promise<string> {
  return await withClient(async (c) => {
    const r = await c.query(
      `INSERT INTO core.projects (tenant_id, customer_id, name, slug, status)
       VALUES ($1, $2, $3, $4, 'active') RETURNING id`,
      [tenantId, customerId, name, name.toLowerCase()],
    );
    return r.rows[0].id as string;
  });
}

/**
 * 直接 SQL 注入 finding(自动建 snapshot + scan_run);返回新 finding id。
 */
export async function seedFindingViaSql(tenantId: string, customerId: string, projectId: string, severity = 'high'): Promise<string> {
  return await withClient(async (c) => {
    const snap = await c.query(
      `INSERT INTO detection.snapshots (project_id, tenant_id, customer_id, branch, commit_sha, asset_hash, file_count, total_size_bytes)
       VALUES ($1, $2, $3, 'main', 'abc', 'def', 1, 100) RETURNING id`,
      [projectId, tenantId, customerId],
    );
    const scan = await c.query(
      `INSERT INTO detection.scan_runs (project_id, snapshot_id, tenant_id, customer_id, trigger_type, incremental_mode, status)
       VALUES ($1, $2, $3, $4, 'manual', 'call_graph', 'done') RETURNING id`,
      [projectId, snap.rows[0].id, tenantId, customerId],
    );
    const r = await c.query(
      `INSERT INTO detection.findings
        (tenant_id, customer_id, project_id, scan_run_id, snapshot_id, rule_id,
         fingerprint, severity, status, title, file_path, start_line, end_line)
       SELECT $1, $2, $3, $4, $5,
        (SELECT id FROM detection.rules WHERE default_enabled = true LIMIT 1),
        $6, $7::severity_enum, 'open', 'Test', '/src/test.ts', 1, 5
       RETURNING id`,
      [tenantId, customerId, projectId, scan.rows[0].id, snap.rows[0].id,
       `fp-${Math.random().toString(36).slice(2, 10)}`, severity],
    );
    return r.rows[0].id as string;
  });
}