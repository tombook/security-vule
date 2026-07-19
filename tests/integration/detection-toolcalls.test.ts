// tests/integration/detection-toolcalls.test.ts
//
// Integration tests for the four tool-call endpoints added to
// /provider/v1/detection:
//   - PATCH  /engines/:id               (toggle)
//   - POST   /engines/:id/health-check  (probe)
//   - POST   /engines/:id/sync          (rule refresh)
//   - POST   /scans/trigger            (manual scan)
//
// These tests stand up the full API child process (per tests/helpers/api.ts)
// so the routes run against the live Postgres on localhost:5433 and the
// full auth + tenant middleware chain. Postgres must be reachable
// (docker compose up postgres).

import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test';
import { Pool } from 'pg';
import { setGuc, closePool, truncateAll, withClient } from '../helpers/db';

// Direct Pool() instances inside the test need the same DATABASE_URL
// the rest of the suite uses. tests/helpers/db.ts centralises it; we
// just read process.env which has already been set by the test runner
// (or fall back to the dev default).
const DATABASE_URL = process.env.DATABASE_URL
  ?? 'postgresql://security_vule:dev_password@localhost:5433/security_vule';
import {
  ensureApiRunning, stopApi,
  TOKENS, httpGet, httpPost, httpPatch, httpPut, httpDelete,
  signTestJwt,
} from '../helpers/api';
import { seedAll, TENANT_A, CUSTOMER_C, USERS } from '../helpers/seed';
import { randomUUID } from 'crypto';

const ENG_GLOBAL   = '00000000-0000-0000-0000-00000000e001'; // semgrep built-in
const ENG_TENANT_A = '00000000-0000-0000-0000-00000000e002'; // per-tenant
const PROJECT_ID   = '00000000-0000-0000-0000-00000000a0aa'; // unique to this test, tenant-A owned
const CUSTOMER_A   = '00000000-0000-0000-0000-00000000a0a0';

// ── helpers ────────────────────────────────────────────────────────────
async function ensureEngine(tenantId: string | null, id: string, name: string) {
  const p = new Pool({ connectionString: DATABASE_URL });
  try {
    await p.query(
      `INSERT INTO detection.engines (id, tenant_id, name, engine_type, version, enabled)
       VALUES ($1, $2, $3, 'semgrep', '1.95.0', true)
       ON CONFLICT (id) DO NOTHING`,
      [id, tenantId, name],
    );
  } finally { await p.end(); }
}

async function ensureDefaultPolicy(tenantId: string) {
  const p = new Pool({ connectionString: DATABASE_URL });
  try {
    const pol = await p.query(
      `INSERT INTO detection.policy_configs
         (tenant_id, scope, name, is_default, severity_threshold,
          incremental_mode, auto_scan_on_sync)
       VALUES ($1, 'tenant', 'Test Default', true, 'medium', 'full', false)
       ON CONFLICT DO NOTHING
       RETURNING id`,
      [tenantId],
    );
    if (pol.rows[0]) {
      await p.query(
        `INSERT INTO detection.policy_versions (policy_id, snapshot, changed_by, change_note)
         VALUES ($1, '{}'::jsonb, $2, 'test')`,
        [pol.rows[0].id, USERS.ownerA],
      );
    }
  } finally { await p.end(); }
}

async function ensureProject(tenantId: string, customerId: string, id: string) {
  const p = new Pool({ connectionString: DATABASE_URL });
  try {
    await p.query(
      `INSERT INTO core.projects (id, tenant_id, customer_id, name, slug)
       VALUES ($1, $2, $3, 'Test Project', 'test-project')
       ON CONFLICT DO NOTHING`,
      [id, tenantId, customerId],
    );
  } finally { await p.end(); }
}

describe('integration: detection tool-call endpoints', () => {
  beforeAll(async () => {
    await ensureApiRunning();
    await truncateAll();
    await seedAll();
    await ensureEngine(null, ENG_GLOBAL, 'Global Semgrep');
    await ensureEngine(TENANT_A, ENG_TENANT_A, 'Tenant-A Semgrep');
    await ensureDefaultPolicy(TENANT_A);
    await ensureProject(TENANT_A, CUSTOMER_C, PROJECT_ID); // CUSTOMER_C is seeded under TENANT_A
  }, 60_000);

  afterAll(async () => {
    await stopApi();
    await closePool();
  });

  // ── PATCH /engines/:id ───────────────────────────────────────────────
  describe('PATCH /engines/:id  (toggle)', () => {
    test('per-tenant engine: toggle off then on returns 200', async () => {
      const tok = TOKENS.ownerA();
      const off = await httpPatch(`/api/provider/v1/detection/engines/${ENG_TENANT_A}`, { enabled: false }, tok);
      expect(off.status).toBe(200);
      expect(off.body.enabled).toBe(false);

      const on = await httpPatch(`/api/provider/v1/detection/engines/${ENG_TENANT_A}`, { enabled: true }, tok);
      expect(on.status).toBe(200);
      expect(on.body.enabled).toBe(true);
    });

    test('global engine (tenant_id IS NULL): 404 (admin-managed)', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPatch(`/api/provider/v1/detection/engines/${ENG_GLOBAL}`, { enabled: false }, tok);
      expect(res.status).toBe(404);
    });

    test('missing body: 400', async () => {
      const tok = TOKENS.ownerA();
      // Send {} — no enabled key. We bypass the typed helper and call raw
      // so the body is genuinely empty. The contract we pin here is
      // "missing/invalid body returns 400" — we don't try to read
      // res.json() because Hono may return an empty body for some
      // 4xx responses, and that is itself acceptable behaviour.
      const res = await fetch(`http://localhost:3000/api/provider/v1/detection/engines/${ENG_TENANT_A}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${await signTestJwt(tok)}` },
        body: '{}',
      });
      expect(res.status).toBe(400);
    });

    test('enabled:non-boolean: 400', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPatch(`/api/provider/v1/detection/engines/${ENG_TENANT_A}`, { enabled: 'yes' as any }, tok);
      expect(res.status).toBe(400);
    });
  });

  // ── POST /engines/:id/health-check ───────────────────────────────────
  describe('POST /engines/:id/health-check', () => {
    test('per-tenant engine: 200 + health record + engines row updated', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPost(`/api/provider/v1/detection/engines/${ENG_TENANT_A}/health-check`, {}, tok);
      expect(res.status).toBe(200);
      expect(res.body.healthStatus).toMatch(/^(healthy|degraded|unhealthy|unknown)$/);
      expect(typeof res.body.latencyMs).toBe('number');
      expect(res.body.latencyMs).toBeGreaterThanOrEqual(0);

      // The engines row should reflect the new last_health_check_at.
      const list = await httpGet('/api/provider/v1/detection/engines', tok);
      const eng = list.body.items.find((e: any) => e.id === ENG_TENANT_A);
      expect(eng).toBeDefined();
      expect(eng.lastHealthCheckAt).not.toBeNull();
    });

    test('global engine: also allowed (tenant_id IS NULL row still probeable)', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPost(`/api/provider/v1/detection/engines/${ENG_GLOBAL}/health-check`, {}, tok);
      expect(res.status).toBe(200);
    });

    test('non-existent engine: 404', async () => {
      const tok = TOKENS.ownerA();
      const fake = randomUUID();
      const res = await httpPost(`/api/provider/v1/detection/engines/${fake}/health-check`, {}, tok);
      expect(res.status).toBe(404);
    });

    test('health_checks row was inserted', async () => {
      // Just confirm the table gained a row.
      const p = new Pool({ connectionString: DATABASE_URL });
      try {
        const r = await p.query(
          `SELECT count(*)::int AS n FROM detection.engine_health_checks
            WHERE engine_id = $1`,
          [ENG_TENANT_A],
        );
        expect(r.rows[0].n).toBeGreaterThan(0);
      } finally { await p.end(); }
    });
  });

  // ── POST /engines/:id/sync ───────────────────────────────────────────
  describe('POST /engines/:id/sync', () => {
    test('returns 200 + rulesTouched count', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPost(`/api/provider/v1/detection/engines/${ENG_TENANT_A}/sync`, {}, tok);
      expect(res.status).toBe(200);
      expect(res.body.engineId).toBe(ENG_TENANT_A);
      expect(typeof res.body.rulesTouched).toBe('number');
      // ENG_TENANT_A has no rules seeded — touch count is 0.
      expect(res.body.rulesTouched).toBe(0);
    });
  });

  // ── POST /scans/trigger ─────────────────────────────────────────────
  describe('POST /scans/trigger', () => {
    test('valid projectId: 200 + queued scan_runs row', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPost('/api/provider/v1/detection/scans/trigger',
        { projectId: PROJECT_ID }, tok);
      expect(res.status).toBe(200);
      expect(res.body.id).toBeDefined();
      expect(res.body.status).toBe('queued');

      // Confirm the row landed in the DB.
      const p = new Pool({ connectionString: DATABASE_URL });
      try {
        const r = await p.query(
          `SELECT id, status, trigger_type FROM detection.scan_runs
            WHERE id = $1 AND tenant_id = $2`,
          [res.body.id, TENANT_A],
        );
        expect(r.rows.length).toBe(1);
        expect(r.rows[0].status).toBe('queued');
        expect(r.rows[0].trigger_type).toBe('manual');
      } finally { await p.end(); }
    });

    test('incremental flag is respected', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPost('/api/provider/v1/detection/scans/trigger',
        { projectId: PROJECT_ID, incremental: true }, tok);
      expect(res.status).toBe(200);

      const p = new Pool({ connectionString: DATABASE_URL });
      try {
        const r = await p.query(
          `SELECT incremental_mode FROM detection.scan_runs WHERE id = $1`,
          [res.body.id],
        );
        // The DB enum is {file, call_graph, full}; the API maps the
        // boolean ?incremental flag onto 'call_graph' (the more useful
        // delta of the two — diff_only would need a baseline snapshot).
        // The full (incremental:false) path uses 'full'.
        expect(r.rows[0].incremental_mode).toBe('call_graph');
      } finally { await p.end(); }
    });

    test('missing projectId: 400 bad_request', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPost('/api/provider/v1/detection/scans/trigger', {}, tok);
      expect(res.status).toBe(400);
    });

    test('non-existent projectId: 404 not_found', async () => {
      const tok = TOKENS.ownerA();
      const res = await httpPost('/api/provider/v1/detection/scans/trigger',
        { projectId: randomUUID() }, tok);
      expect(res.status).toBe(404);
    });
  });
});