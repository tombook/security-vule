#!/usr/bin/env bun
/**
 * scripts/seed-detection-fixtures.ts
 *
 * Seeds the demo detection fixtures that the Detection Center UI needs
 * before its first page load can show something useful:
 *   - 6 detection.engines rows (5 global built-ins + 1 per-tenant
 *     custom engine so the toggle endpoint has something to flip)
 *   - 1 core.projects row (needed for POST /detection/scans/trigger
 *     to have a target project)
 *   - 1 default detection.policy_configs + policy_versions row (the
 *     scan-trigger endpoint reads the tenant's default policy version)
 *
 * Idempotent — every INSERT is ON CONFLICT DO NOTHING. Safe to re-run.
 *
 *   bun run scripts/seed-detection-fixtures.ts
 */

import { Pool } from 'pg';

const DATABASE_URL = process.env.DATABASE_URL
  ?? 'postgresql://security_vule:dev_password@localhost:5433/security_vule';

const TENANT_ID   = '11111111-1111-1111-1111-111111111111';
const CUSTOMER_ID = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const PROJECT_ID  = '99999999-9999-9999-9999-999999999999';
const USER_ID     = '22222222-2222-2222-2222-222222222222';

const pool = new Pool({ connectionString: DATABASE_URL });
try {
  // 1. Engines — 5 built-in (global, tenant_id = NULL) + 1 custom (tenant-owned)
  await pool.query(
    `INSERT INTO detection.engines (tenant_id, name, engine_type, version, enabled)
     VALUES
       (NULL, 'Semgrep',        'semgrep',         '1.95.0', true),
       (NULL, 'Trivy',          'trivy',           '0.58.1', true),
       (NULL, 'Bandit',         'bandit',          '1.7.10', true),
       (NULL, 'Gosec',          'gosec',           '2.22.4', true),
       (NULL, 'DFG Custom',     'dfg_custom',      '2.0.0',  true),
       (NULL, 'ESLint Security','eslint_security', '3.0.0',  true),
       ($1,   'My Custom Semgrep','semgrep',        '1.95.0', true)
     ON CONFLICT DO NOTHING`,
    [TENANT_ID],
  );

  // 2. Demo project (manual scan trigger needs a target)
  await pool.query(
    `INSERT INTO core.projects (id, tenant_id, customer_id, name, slug)
     VALUES ($1, $2, $3, 'Demo Project', 'demo-project')
     ON CONFLICT DO NOTHING`,
    [PROJECT_ID, TENANT_ID, CUSTOMER_ID],
  );

  // 3. Default policy + version (scan-trigger reads default policy head)
  const pol = await pool.query(
    `INSERT INTO detection.policy_configs
       (tenant_id, scope, name, is_default, severity_threshold,
        incremental_mode, auto_scan_on_sync)
     VALUES ($1, 'tenant', 'Default Policy', true, 'medium', 'full', false)
     ON CONFLICT DO NOTHING
     RETURNING id`,
    [TENANT_ID],
  );

  // Only create a policy_version if the policy_configs insert produced a new row
  // (otherwise the version already exists too and we don't want duplicates).
  if (pol.rows[0]) {
    await pool.query(
      `INSERT INTO detection.policy_versions
         (policy_id, snapshot, changed_by, change_note)
       VALUES ($1, '{}'::jsonb, $2, 'seed')`,
      [pol.rows[0].id, USER_ID],
    );
  }

  const counts = await pool.query(`
    SELECT
      (SELECT count(*)::int FROM detection.engines)            AS engines,
      (SELECT count(*)::int FROM core.projects WHERE deleted_at IS NULL) AS projects,
      (SELECT count(*)::int FROM detection.policy_configs)    AS policies,
      (SELECT count(*)::int FROM detection.policy_versions)   AS policy_versions
  `);
  console.log('✓ seeded detection fixtures:');
  console.table(counts.rows[0]);
} finally {
  await pool.end();
}