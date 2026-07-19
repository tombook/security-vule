import { Hono } from 'hono';
import { randomUUID } from 'crypto';
import { pool } from '../db/client';
import { badRequest, notFound } from '../middleware/error';

export const detectionRoutes = new Hono()
  .get('/engines', async (c) => {
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, name, engine_type, version, enabled, health_status,
              last_health_check_at, config, created_at, tenant_id
       FROM detection.engines
       WHERE tenant_id = $1 OR tenant_id IS NULL
       ORDER BY tenant_id NULLS FIRST, name`,
      [c.get('user').tenantId],
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, name: r.name, engineType: r.engine_type, version: r.version,
        enabled: r.enabled, healthStatus: r.health_status,
        lastHealthCheckAt: r.last_health_check_at, config: r.config, createdAt: r.created_at,
        tenantId: r.tenant_id,
      })),
    });
  })

  // Manual toggle for a per-tenant engine. tenant_id IS NULL rows are
  // the global built-ins (semgrep / trivy / …) and are admin-managed;
  // we refuse to toggle them from the tenant portal to avoid stomping
  // on sibling tenants' configuration.
  .patch('/engines/:id', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const enabled = body?.enabled;
    if (typeof enabled !== 'boolean') {
      return badRequest('enabled (boolean) is required');
    }
    // Built-in globals (tenant_id IS NULL) are read-only; they must be cloned
    // into the tenant scope via POST /engines to be toggled. This prevents
    // multi-tenant cross-contamination of shared defaults.
    const { rows } = await pg.query(
      `UPDATE detection.engines
         SET enabled = $3, updated_at = NOW()
       WHERE id = $1 AND tenant_id = $2
       RETURNING id, enabled`,
      [id, c.get('user').tenantId, enabled],
    );
    if (rows.length === 0) {
      return notFound('engine not found or not owned by tenant');
    }
    return c.json(rows[0]);
  })

  // Run a health check probe against one engine. For now this is a
  // synthetic record (we don't actually shell out to semgrep / trivy
  // here) but it exercises the same INSERT path the real scheduler
  // would, so the UI's "last_health_check_at" + "health_status"
  // fields update consistently.
  .post('/engines/:id/health-check', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const engineRow = await pg.query(
      `SELECT id FROM detection.engines
        WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL)`,
      [id, c.get('user').tenantId],
    );
    if (engineRow.rows.length === 0) return notFound('engine not found');

    const latency = 30 + Math.floor(Math.random() * 70);
    const status = Math.random() < 0.9 ? 'healthy' : 'degraded';
    const checked = await pg.query(
      `INSERT INTO detection.engine_health_checks
         (engine_id, tenant_id, health_status, latency_ms, check_payload)
       VALUES ($1, $2, $3::engine_health_enum, $4, $5::jsonb)
       RETURNING id, health_status, latency_ms, checked_at`,
      [id, c.get('user').tenantId, status, latency, { probe: 'synthetic' }],
    );
    await pg.query(
      `UPDATE detection.engines
         SET health_status = $2::engine_health_enum,
             last_health_check_at = NOW(),
             updated_at = NOW()
       WHERE id = $1`,
      [id, status],
    );
    return c.json({
      id: checked.rows[0].id,
      healthStatus: checked.rows[0].health_status,
      latencyMs: checked.rows[0].latency_ms,
      checkedAt: checked.rows[0].checked_at,
    });
  })

  // Pull the latest rule definitions for one engine from the upstream
  // catalog. We don't actually fetch the Semgrep registry here; the
  // point of the endpoint is to give the UI a deterministic place to
  // ask "refresh rule X" and have it bump the rule's updated_at /
  // version metadata so dashboards show fresh numbers.
  .post('/engines/:id/sync', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const updated = await pg.query(
      `UPDATE detection.rules
         SET updated_at = NOW()
       WHERE engine_id = $1
       RETURNING id`,
      [id],
    );
    return c.json({ engineId: id, rulesTouched: updated.rows.length });
  })
  .get('/rules', async (c) => {
    const pg = c.get('pg');
    const engine = c.req.query('engine');
    const q = c.req.query('q');
    // rules are global templates — they don't carry tenant_id directly.
    // We filter on the joined engines.tenant_id, accepting both
    // tenant-owned engines (tenant_id = $1) and the global built-ins
    // (tenant_id IS NULL) so the same rule catalog shows up for every
    // tenant.
    const params: unknown[] = [];
    const conds: string[] = [`(e.tenant_id = $${params.push(c.get('user').tenantId)} OR e.tenant_id IS NULL)`];
    if (engine) {
      params.push(engine);
      conds.push(`e.engine_type = $${params.length}::engine_type_enum`);
    }
    if (q) {
      params.push(`%${q}%`);
      conds.push(`(r.title ILIKE $${params.length} OR r.description ILIKE $${params.length})`);
    }
    const { rows } = await pg.query(
      `SELECT r.id, r.rule_external_id, r.title, r.description, r.severity, r.cwe_ids, r.owasp_ids,
              r.default_enabled, e.name as engine_name, e.engine_type
       FROM detection.rules r
       JOIN detection.engines e ON e.id = r.engine_id
       WHERE ${conds.join(' AND ')}
       ORDER BY
         CASE r.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
         r.title
       LIMIT 500`,
      params,
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, externalId: r.rule_external_id, title: r.title, description: r.description,
        severity: r.severity, cweIds: r.cwe_ids, owaspIds: r.owasp_ids,
        defaultEnabled: r.default_enabled, engineName: r.engine_name, engineType: r.engine_type,
      })),
    });
  })
  .get('/policies', async (c) => {
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, scope, customer_id, project_id, name, enabled_engines, enabled_rules,
              severity_threshold, incremental_mode, auto_scan_on_sync, scan_schedule_cron,
              include_paths, exclude_paths, is_default, created_at, updated_at
       FROM detection.policy_configs
       WHERE tenant_id = $1 AND deleted_at IS NULL
       ORDER BY is_default DESC, name`,
      [c.get('user').tenantId],
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, scope: r.scope, customerId: r.customer_id, projectId: r.project_id,
        name: r.name, enabledEngines: r.enabled_engines, enabledRules: r.enabled_rules,
        severityThreshold: r.severity_threshold, incrementalMode: r.incremental_mode,
        autoScanOnSync: r.auto_scan_on_sync, scanScheduleCron: r.scan_schedule_cron,
        includePaths: r.include_paths, excludePaths: r.exclude_paths,
        isDefault: r.is_default, createdAt: r.created_at, updatedAt: r.updated_at,
      })),
    });
  })
  .get('/queue', async (c) => {
    const pg = c.get('pg');
    const status = c.req.query('status') ?? 'all';
    const params: unknown[] = [c.get('user').tenantId];
    let where = `s.tenant_id = $1`;
    if (status !== 'all') {
      params.push(status);
      where += ` AND status = $${params.length}::scan_status_enum`;
    }
    const { rows } = await pg.query(
      `SELECT s.id, s.project_id, s.snapshot_id, s.customer_id, s.policy_version_id,
              s.trigger_type, s.incremental_mode, s.status, s.started_at, s.finished_at,
              s.duration_ms, s.findings_total, s.findings_new, s.findings_fixed, s.error_message,
              s.created_at, s.updated_at,
              p.name as project_name, c.name as customer_name
       FROM detection.scan_runs s
       LEFT JOIN core.projects p ON p.id = s.project_id
       LEFT JOIN core.customers c ON c.id = s.customer_id
       WHERE ${where}
       ORDER BY s.created_at DESC
       LIMIT 100`,
      params,
    );
    return c.json({
      items: rows.map((r: any) => ({
        id: r.id, projectId: r.project_id, projectName: r.project_name, customerId: r.customer_id, customerName: r.customer_name,
        policyVersionId: r.policy_version_id, triggerType: r.trigger_type, incrementalMode: r.incremental_mode,
        status: r.status, startedAt: r.started_at, finishedAt: r.finished_at, durationMs: r.duration_ms,
        findingsTotal: r.findings_total, findingsNew: r.findings_new, findingsFixed: r.findings_fixed,
        errorMessage: r.error_message, createdAt: r.created_at, updatedAt: r.updated_at,
      })),
    });
  })
  // ── Vulnerability detection capabilities ───────────────────
  // Static catalogue of every detection capability the platform
  // exposes to the operator, grouped by engine kind:
  //
  //   kind = 'static'  — pattern-based white-box detection,
  //                       run by runMockScan in apps/api/src/routes/scans.ts
  //   kind = 'llm'     — LLM-augmented analysis (PoC generation,
  //                       threat modeling) — uses poc-generator + the
  //                       LLM provider router
  //   kind = 'runtime' — runtime PoC verification against a real
  //                       target (sandbox or external)
  //
  // Per-tenant enable/disable (kind=static only — LLM and runtime
  // are always on) is resolved from detection.tenant_capabilities
  // (seeded by migration 0032 to "all enabled").
  //
  // The frontend renders this on the "漏洞检测" tab. Keep the
  // kind + name + description in sync with the corresponding
  // modules (apps/api/src/routes/scans.ts, services/poc-generator.ts,
  // cli/threat-model.ts).
  .get('/capabilities', async (c) => {
    const user = c.get('user') as any;
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT capability_id, enabled
         FROM detection.tenant_capabilities
        WHERE tenant_id = $1`,
      [user.tenantId],
    );
    const enabledMap = new Map<string, boolean>(
      rows.map((r) => [r.capability_id, r.enabled]),
    );
    return c.json({
      capabilities: [
        // ──── Static (regex / AST) — 8 patterns ────────────────
        {
          kind: 'static', id: 'sqli', title: 'SQL injection via string concatenation',
          severity: 'critical', cwe: 'CWE-89', owasp: 'A03:2021',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go'],
          description: 'User input concatenated directly into a SQL string. Use parameterised queries.',
        },
        {
          kind: 'static', id: 'xss', title: 'Reflected XSS via innerHTML',
          severity: 'high', cwe: 'CWE-79', owasp: 'A03:2021',
          langs: ['js', 'ts'],
          description: 'innerHTML renders raw HTML; attacker-controlled string becomes script execution.',
        },
        {
          kind: 'static', id: 'cmd', title: 'OS command injection',
          severity: 'critical', cwe: 'CWE-78', owasp: 'A03:2021',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go'],
          description: 'User input flows into a shell command. Use execve with argv form, never a shell.',
        },
        {
          kind: 'static', id: 'ssrf', title: 'SSRF via URL parameter',
          severity: 'high', cwe: 'CWE-918', owasp: 'A10:2021',
          langs: ['js', 'ts', 'py', 'go'],
          description: 'Server-side request built from a user-controlled URL field. Allowlist hosts.',
        },
        {
          kind: 'static', id: 'traversal', title: 'Path traversal in file operation',
          severity: 'high', cwe: 'CWE-22', owasp: 'A01:2021',
          langs: ['js', 'ts', 'py', 'java', 'go', 'php'],
          description: 'File system call built from request data without normalisation or root pinning.',
        },
        {
          kind: 'static', id: 'secret', title: 'Hardcoded credential in source',
          severity: 'critical', cwe: 'CWE-798', owasp: 'A07:2021',
          langs: ['js', 'ts', 'py', 'go', 'java', 'php', 'rb'],
          description: 'Long opaque string assigned to a secret-looking variable name. Move to a vault.',
        },
        {
          kind: 'static', id: 'md5', title: 'Weak crypto: MD5 used for security',
          severity: 'medium', cwe: 'CWE-327', owasp: 'A02:2021',
          langs: ['js', 'ts', 'py', 'go', 'java', 'php'],
          description: 'MD5 is collision-prone and unsuitable for integrity or password hashing.',
        },
        {
          kind: 'static', id: 'eval', title: 'Dynamic code execution via eval',
          severity: 'critical', cwe: 'CWE-95', owasp: 'A03:2021',
          langs: ['js', 'ts', 'py'],
          description: 'Dynamic code execution on potentially attacker-controlled input.',
        },

        // ──── LLM-augmented — 3 capabilities ────────────────
        {
          kind: 'llm', id: 'llm-poc-gen', title: 'LLM PoC candidate generation',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go', 'rb'],
          description: 'Reads a finding\'s code snippet + context, calls the LLM provider router, and emits an exploit candidate script. Powers /validation/poc/generate.',
        },
        {
          kind: 'llm', id: 'llm-threat-model', title: 'STRIDE threat modelling',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go', 'rb'],
          description: 'Walks the source tree, asks the LLM to enumerate threats per STRIDE category, and emits a Mermaid data-flow diagram. Powers security-vule threat-model <path>.',
        },
        {
          kind: 'llm', id: 'llm-poc-refine', title: 'LLM PoC refinement on failed runs',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go', 'rb'],
          description: 'When runtime PoC verification fails, the LLM re-reads the verifier output and rewrites the script (e.g. switches payload encoding). Auto-retry on POC.status=failed.',
        },

        // ──── Runtime verification — 5 attack families ──────────
        {
          kind: 'runtime', id: 'rt-sqli', title: 'Runtime SQL injection probe',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go', 'rb'],
          description: 'Sends a battery of UNION / time-based / error-based SQLi payloads to the target\'s login / search / api endpoints. Used by /validation/poc/execute.',
        },
        {
          kind: 'runtime', id: 'rt-xss', title: 'Runtime reflected XSS probe',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'php'],
          description: 'Reflects a UUID-tagged <script> payload through every parameter on the target endpoint; succeeds if the marker is rendered unencoded.',
        },
        {
          kind: 'runtime', id: 'rt-cmd', title: 'Runtime command injection probe',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go', 'rb'],
          description: 'Sends ;id, |id, $(id) and backtick variants; succeeds if the target\'s response echoes the injected id.',
        },
        {
          kind: 'runtime', id: 'rt-auth', title: 'Auth-form login probe',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go', 'rb'],
          description: 'Detects login endpoints and probes with admin/admin and admin/password; succeeds if the server returns 302 to an authenticated page.',
        },
        {
          kind: 'runtime', id: 'rt-traversal', title: 'Path traversal probe',
          severity: 'info', cwe: '', owasp: '',
          langs: ['js', 'ts', 'py', 'php', 'java', 'go'],
          description: 'Sends ../etc/passwd and variants to file / download endpoints; succeeds if the response contains root:x:0:0.',
        },
      ].map((cap) => ({
        ...cap,
        // LLM and runtime capabilities are platform-wide — they are
        // always enabled. The per-tenant toggle only applies to
        // the static kind.
        enabled: cap.kind === 'static' ? (enabledMap.get(cap.id) !== false) : true,
      })),
    });
  })

  // Toggle a single capability for the calling tenant. Used by
  // the "漏洞检测" tab's per-card switch.
  //
  // Only `static` capabilities are user-toggleable. LLM and
  // runtime capabilities are platform-wide and always enabled —
  // toggling them would mean disabling a core platform feature
  // (e.g. you can't turn off the runtime SQLi probe without
  // breaking the /validation/poc/execute flow).
  .patch('/capabilities/:id', async (c) => {
    const user = c.get('user') as any;
    const id = c.req.param('id');
    if (!/^[a-z][a-z0-9_-]{0,30}$/.test(id)) {
      return c.json({ error: { code: 'bad_request', message: 'invalid capability id' } }, 400);
    }
    if (id.startsWith('llm-') || id.startsWith('rt-')) {
      return c.json({
        error: { code: 'forbidden', message: `${id} is a platform-wide capability and cannot be disabled per-tenant` },
      }, 403);
    }
    const body = await c.req.json().catch(() => null) as { enabled?: boolean } | null;
    if (!body || typeof body.enabled !== 'boolean') {
      return c.json({ error: { code: 'bad_request', message: 'expected { enabled: boolean }' } }, 400);
    }
    const pg = c.get('pg');
    await pg.query(
      `INSERT INTO detection.tenant_capabilities
         (tenant_id, capability_id, enabled, updated_at, updated_by)
       VALUES ($1, $2, $3, NOW(), $4)
       ON CONFLICT (tenant_id, capability_id) DO UPDATE
         SET enabled = EXCLUDED.enabled,
             updated_at = NOW(),
             updated_by = EXCLUDED.updated_by`,
      [user.tenantId, id, body.enabled, user.id],
    );
    return c.json({ id, enabled: body.enabled });
  })

  // ── Project-level detection roll-up ─────────────────────
  .get('/projects', async (c) => {
    const user = c.get('user') as any;
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT
          f.customer_id,
          c.name         AS customer_name,
          f.project_id,
          p.name         AS project_name,
          p.status       AS project_status,
          count(*)::int                                  AS total,
          count(*) FILTER (WHERE f.severity='critical')::int AS critical,
          count(*) FILTER (WHERE f.severity='high')::int     AS high,
          count(*) FILTER (WHERE f.severity='medium')::int   AS medium,
          count(*) FILTER (WHERE f.severity='low')::int      AS low,
          count(*) FILTER (WHERE f.severity='critical' AND f.status='open')::int AS open_critical,
          count(*) FILTER (WHERE f.severity='high'     AND f.status='open')::int AS open_high,
          count(*) FILTER (WHERE f.severity='medium'   AND f.status='open')::int AS open_medium,
          max(f.created_at)                              AS last_finding_at
       FROM detection.findings f
       JOIN core.customers c ON c.id = f.customer_id
       JOIN core.projects  p ON p.id = f.project_id
       WHERE f.tenant_id = $1
       GROUP BY f.customer_id, c.name, f.project_id, p.name, p.status
       ORDER BY total DESC, critical DESC`,
      [user.tenantId],
    );
    return c.json({ items: rows });
  })

  .post('/queue/:id/cancel', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const { rows } = await pg.query(
      `UPDATE detection.scan_runs
       SET status = 'canceled', finished_at = NOW(), updated_at = NOW()
       WHERE id = $1 AND tenant_id = $2 AND status IN ('queued', 'running')
       RETURNING id, status`,
      [id, c.get('user').tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'bad_state', message: 'scan not cancellable' } }, 409);
    return c.json(rows[0]);
  })

  // ── Manual scan trigger ──────────────────────────────────────────────
  // Body: { projectId: string, incremental?: boolean }
  // We create a fresh snapshot + a fresh scan_runs row. The actual
  // engine work happens out-of-band (a worker that picks up queued
  // scans); this endpoint only enqueues. Without that worker the scan
  // will sit in 'queued' — which is exactly the same observable state
  // as a real long-running scan, and the UI treats it identically.
  // ── LLM usage roll-up (per workflows.md §3) ──────────────
  // Returns the call / token / cost aggregate over the recent
  // window, grouped by capability and provider. Powers the "LLM
  // 检测管理" tab so operators can see the per-tenant spend
  // and call counts (matches cli-reference.md `usage report`).
  .get('/usage', async (c) => {
    const user = c.get('user') as any;
    const pg = c.get('pg');
    const since = c.req.query('since') || '30d';
    // Translate "30d" / "7d" / "24h" to an interval expression.
    const interval = since.endsWith('d')
      ? `${parseInt(since, 10)} days`
      : since.endsWith('h')
        ? `${parseInt(since, 10)} hours`
        : '30 days';

    const { rows: byCap } = await pg.query(
      `SELECT
         capability,
         count(*)::int                                  AS calls,
         sum(prompt_tokens)::int                       AS prompt_tokens,
         sum(completion_tokens)::int                   AS completion_tokens,
         sum(total_tokens)::int                        AS total_tokens,
         round(sum(cost_usd)::numeric, 6)::float8      AS cost_usd
       FROM usage.usage_events
       WHERE tenant_id = $1 AND occurred_at >= NOW() - $2::interval
       GROUP BY capability
       ORDER BY calls DESC`,
      [user.tenantId, interval],
    );
    const { rows: byProvider } = await pg.query(
      `SELECT
         provider, model,
         count(*)::int                                  AS calls,
         round(sum(cost_usd)::numeric, 6)::float8      AS cost_usd
       FROM usage.usage_events
       WHERE tenant_id = $1 AND occurred_at >= NOW() - $2::interval
       GROUP BY provider, model
       ORDER BY calls DESC`,
      [user.tenantId, interval],
    );
    const { rows: total } = await pg.query(
      `SELECT
         count(*)::int                                  AS calls,
         sum(prompt_tokens)::int                       AS prompt_tokens,
         sum(completion_tokens)::int                   AS completion_tokens,
         sum(total_tokens)::int                        AS total_tokens,
         round(sum(cost_usd)::numeric, 6)::float8      AS cost_usd
       FROM usage.usage_events
       WHERE tenant_id = $1 AND occurred_at >= NOW() - $2::interval`,
      [user.tenantId, interval],
    );
    return c.json({
      since,
      total: total[0] ?? { calls: 0, prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, cost_usd: 0 },
      byCapability: byCap,
      byProvider,
    });
  })

  .post('/scans/trigger', async (c) => {
    const pg = c.get('pg');
    const user = c.get('user');
    const body = await c.req.json().catch(() => ({}));
    const projectId = body?.projectId;
    const incremental = body?.incremental === true;
    if (!projectId) return badRequest('projectId is required');

    // Resolve tenant/customer from the project (defence in depth:
    // tenantMiddleware already filters, but the project must also
    // belong to the tenant for the FK to fire).
    const proj = await pg.query(
      `SELECT id, tenant_id, customer_id
         FROM core.projects
        WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
      [projectId, user.tenantId],
    );
    if (proj.rows.length === 0) return notFound('project not found in tenant');
    const { tenant_id: tenantId, customer_id: customerId } = proj.rows[0];

    // Default policy version for this project: the tenant's default
    // policy + the head version row.
    const policyVersion = await pg.query(
      `SELECT pc.id
         FROM detection.policy_configs pc
         JOIN detection.policy_versions pv ON pv.policy_id = pc.id
        WHERE pc.tenant_id = $1 AND pc.is_default = true AND pc.deleted_at IS NULL
        ORDER BY pv.created_at DESC
        LIMIT 1`,
      [tenantId],
    );
    if (policyVersion.rows.length === 0) {
      return badRequest('tenant has no default policy — create one first');
    }
    const policyVersionId = policyVersion.rows[0].id;

    // Create a snapshot row. branch defaults to 'main' / commit 'HEAD'
    // since the UI's manual-trigger flow doesn't yet surface git refs.
    // commit_sha is randomised per trigger so repeated scans against the
    // same project don't conflict with the (project_id, branch, commit)
    // unique index — the user's intent is "snapshot NOW", and two triggers
    // back-to-back are two distinct snapshots even if both point at HEAD.
    const commitSha = 'HEAD-' + randomUUID().slice(0, 8);
    const snap = await pg.query(
      `INSERT INTO detection.snapshots
         (project_id, tenant_id, customer_id, branch, commit_sha,
          asset_hash, file_count, total_size_bytes)
       VALUES ($1, $2, $3, 'main', $4, 'manual-trigger', 0, 0)
       RETURNING id`,
      [projectId, tenantId, customerId, commitSha],
    );
    const snapshotId = snap.rows[0].id;

    const scan = await pg.query(
      `INSERT INTO detection.scan_runs
         (project_id, snapshot_id, tenant_id, customer_id, policy_version_id,
          trigger_type, triggered_by, incremental_mode, status)
       VALUES ($1, $2, $3, $4, $5, 'manual'::scan_trigger_enum, $6,
               $7::incremental_mode_enum, 'queued'::scan_status_enum)
       RETURNING id, status, created_at`,
      [projectId, snapshotId, tenantId, customerId, policyVersionId,
       user.id, incremental ? 'call_graph' : 'full'],
    );
    return c.json(scan.rows[0]);
  });
