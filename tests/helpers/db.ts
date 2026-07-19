// tests/helpers/db.ts
// 测试数据库助手:连接池、TRUNCATE、reset、GUC 设置
// @ts-expect-error pg 来自 apps/api 的依赖,通过 bun workspace 解析
import { Pool, type PoolClient } from 'pg';

const DATABASE_URL = process.env.TEST_DATABASE_URL
  ?? process.env.DATABASE_URL
  ?? 'postgresql://security_vule:dev_password@localhost:5433/security_vule';

// ── Self-healing pool ─────────────────────────────────────────────────────
// Bug fixed: 11 test files import this helper into one Bun process. When
// any one file's afterAll(closePool) ended the module-level `pool`, every
// later file's `pool.connect()` blew up with
//   "Cannot use a pool after calling end on the pool"
// killing ~338 tests that had nothing to do with the file that closed it.
//
// Fix:
//   1. `currentPool` is a mutable `let` holding the live Pool.
//   2. The exported `pool` is a Proxy that forwards every property access
//      and method call to `currentPool`. 8 test files do
//      `import { pool } from '../helpers/db'`; the Proxy keeps that API
//      stable while still letting closePool() swap in a fresh instance.
//   3. `withClient` already routes through `connectFresh()` which probes
//      for the "pool ended" error and rebuilds lazily — belt + suspenders.
//   4. `closePool()` ends the current pool and immediately rebuilds so the
//      next test file in the same process starts with a live pool.

let currentPool: Pool = new Pool({ connectionString: DATABASE_URL, max: 20 });

// Proxy: forward everything to the live pool. Tests call pool.connect(),
// pool.query(), pool.end() — all funnel through `get()` to `currentPool`.
export const pool: Pool = new Proxy({} as Pool, {
  get(_target, prop, _receiver) {
    const live = currentPool as unknown as Record<string | symbol, unknown>;
    const value = live[prop as string];
    return typeof value === 'function' ? (value as Function).bind(live) : value;
  },
});

async function connectFresh(): Promise<PoolClient> {
  try {
    return await currentPool.connect();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/pool.*end/i.test(msg)) {
      // Previous test file's afterAll ended the pool before our Proxy
      // got a chance to swap it. Rebuild and retry once.
      currentPool = new Pool({ connectionString: DATABASE_URL, max: 20 });
      return currentPool.connect();
    }
    throw err;
  }
}

export async function withClient<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await connectFresh();
  try { return await fn(client); } finally { client.release(); }
}

export async function setGuc(client: PoolClient, tenantId: string, role: string, customerId?: string): Promise<void> {
  await client.query(`SET LOCAL ROLE authenticated_app`);
  await client.query(`SET LOCAL app.current_tenant = '${tenantId}'`);
  await client.query(`SET LOCAL app.current_user_role = '${role}'`);
  if (customerId) await client.query(`SET LOCAL app.current_customer = '${customerId}'`);
}

export async function clearGuc(client: PoolClient): Promise<void> {
  await client.query(`RESET ROLE`);
  await client.query(`RESET app.current_tenant`);
  await client.query(`RESET app.current_user_role`);
  await client.query(`RESET app.current_customer`);
}

export async function truncateAll(): Promise<void> {
  await withClient(async (c) => {
    await c.query('BEGIN');
    try {
      await c.query(`TRUNCATE TABLE
        governance.audit_logs,
        governance.notifications,
        governance.webhook_deliveries,
        governance.webhooks,
        governance.tenant_data_exports,
        detection.pr_scan_checks,
        detection.finding_comments,
        detection.finding_state_history,
        detection.findings,
        detection.scan_run_engines,
        detection.scan_runs,
        detection.snapshots,
        detection.policy_versions,
        detection.policy_configs,
        detection.rules,
        detection.engine_health_checks,
        detection.engines,
        poc.poc_chat_messages,
        poc.poc_library,
        poc.poc_sandboxes,
        poc.poc_runs,
        poc.exploit_chains,
        integration.ticket_sync_log,
        integration.ticket_integrations,
        usage.quota_alerts,
        usage.quota_policies,
        usage.usage_events,
        billing.invoice_line_items,
        billing.invoices,
        billing.allocation_rules,
        billing.billing_accounts,
        billing.plans,
        core.password_reset_tokens,
        core.api_keys,
        core.sessions,
        core.invites,
        core.contacts,
        core.source_sync_history,
        core.sources,
        core.projects,
        core.reports,
        core.customers,
        core.users,
        core.tenants,
        meta.tenant_applications,
        core.oauth_states
        RESTART IDENTITY CASCADE`);
      await c.query('COMMIT');
    } catch (err) {
      await c.query('ROLLBACK');
      throw err;
    }
  });

  // Re-seed the demo account + a tenant it lives in. Integration tests
  // blow away core.users via the TRUNCATE above, which used to leave the
  // portal at http://localhost:5173/login un-log-in-able after any test
  // run (you'd hit 401 'Invalid email or password'). The demo account
  // is the seeded row from scripts/seed-demo-account.ts — reinserting
  // it here keeps the manual UI smoke-test workflow working regardless
  // of which integration test was the last to run.
  //
  // We use a *dedicated* set of UUIDs that don't collide with any test
  // fixture (TENANT_A=CUSTOMER_C in tests/helpers/seed.ts is on tenant
  // aaaa-...; our demo lives on tenant 1111-... with its own customer
  // and project, so the two never overlap).
  await reSeedDemoAccount();
}

/**
 * Idempotent: insert the demo tenant + user + the small set of detection
 * fixtures the manual smoke tests need (engines, project, default
 * policy). Keeps the user-visible login page working after every test.
 */
export async function reSeedDemoAccount(): Promise<void> {
  // Demo tenant + user live in their own namespace (1111-... tenant)
  // so they never collide with the integration test fixtures (which
  // are on tenant aaaa-... with customer cccc-...).
  const TENANT_ID   = '11111111-1111-1111-1111-111111111111';
  const USER_ID     = '22222222-2222-2222-2222-222222222222';
  const CUSTOMER_ID = 'dddd1111-1111-1111-1111-111111111111'; // was cccc-... but that collides with seed.ts CUSTOMER_C
  const PROJECT_ID  = 'eeee1111-1111-1111-1111-111111111111';
  const bcrypt = await import('bcryptjs');
  const hash = await bcrypt.hash('Admin@123', 12);

  await withClient(async (c) => {
    await c.query(
      `INSERT INTO core.tenants (id, name, slug, status)
       VALUES ($1, 'Demo Tenant', 'demo-tenant', 'active')
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
      [TENANT_ID],
    );
    await c.query(
      `INSERT INTO core.users (id, tenant_id, customer_id, portal, email,
         password_hash, role, status, failed_login_count, mfa_enabled, locked_until)
       VALUES ($1, $2, $3, 'provider', $4, $5,
               'ProviderOwner', 'active', 0, false, NULL)
       ON CONFLICT (tenant_id, email) DO UPDATE SET
         password_hash = EXCLUDED.password_hash,
         role = 'ProviderOwner', portal = 'provider', status = 'active',
         failed_login_count = 0, locked_until = NULL`,
      [USER_ID, TENANT_ID, CUSTOMER_ID, 'admin@demo.com', hash],
    );
    await c.query(
      `INSERT INTO core.customers (id, tenant_id, name, slug)
       VALUES ($1, $2, 'Demo Customer', 'demo-customer')
       ON CONFLICT (id) DO NOTHING`,
      [CUSTOMER_ID, TENANT_ID],
    );
    await c.query(
      `INSERT INTO core.projects (id, tenant_id, customer_id, name, slug)
       VALUES ($1, $2, $3, 'Demo Project', 'demo-project')
       ON CONFLICT (id) DO NOTHING`,
      [PROJECT_ID, TENANT_ID, CUSTOMER_ID],
    );
    // One per-tenant engine (so the toggle / health-check / sync
    // endpoints have something concrete to operate on).
    await c.query(
      `INSERT INTO detection.engines (tenant_id, name, engine_type, version, enabled)
       VALUES ($1, 'My Custom Semgrep', 'semgrep', '1.95.0', true)
       ON CONFLICT DO NOTHING`,
      [TENANT_ID],
    );
    // Default policy + version (needed by /scans/trigger).
    const pol = await c.query(
      `INSERT INTO detection.policy_configs
         (tenant_id, scope, name, is_default, severity_threshold,
          incremental_mode, auto_scan_on_sync)
       VALUES ($1, 'tenant', 'Default Policy', true, 'medium', 'full', false)
       ON CONFLICT DO NOTHING
       RETURNING id`,
      [TENANT_ID],
    );
    if (pol.rows[0]) {
      await c.query(
        `INSERT INTO detection.policy_versions
           (policy_id, snapshot, changed_by, change_note)
         VALUES ($1, '{}'::jsonb, $2, 'auto-reseeded by truncateAll')`,
        [pol.rows[0].id, USER_ID],
      );
    }
  });
}

export async function closePool(): Promise<void> {
  // End current, immediately create a fresh one. Tests that imported
  // `pool` as a Proxy binding will now route to the live fresh pool.
  try { await currentPool.end(); } catch { /* already ended — fine */ }
  currentPool = new Pool({ connectionString: DATABASE_URL, max: 20 });
}