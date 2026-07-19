import { Hono } from 'hono';
import { z } from 'zod';
import { pool } from '../db/client';
import { generatePoC, recordUsageEvent } from '../services/poc-generator';
import { executeInSandbox } from '../services/poc-runner';
import { listMessages, postMessage, autoAssistantReply } from '../services/chat-context';
import { requireRole, PROVIDER_WRITE_ROLES } from '../middleware/rbac';

const generateSchema = z.object({
  findingId: z.string().uuid(),
  capability: z.enum(['poc_gen', 'poc_chat']).default('poc_gen'),
});

const approveSchema = z.object({
  comment: z.string().max(500).optional(),
});

const rejectSchema = z.object({
  reason: z.string().min(1).max(500),
});

const chatSchema = z.object({
  message: z.string().min(1).max(4000),
});

interface PocRunRow {
  id: string;
  tenant_id: string;
  customer_id: string;
  project_id: string;
  finding_id: string;
  source: string;
  poc_script: string;
  poc_script_hash: string;
  status: string;
  exploit_proven: boolean;
  approved_by: string | null;
  approved_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  exit_code: number | null;
  stdout_log: string | null;
  stderr_log: string | null;
  behavior_report: any;
  evidence_url: string | null;
  error_message: string | null;
  target_id: string | null;
  http_status: number | null;
  stdout: string | null;
  created_at: string;
  updated_at: string;
  finding_title: string;
  finding_severity: string;
  finding_file: string;
  finding_line: number;
}

function rowToPocRun(r: PocRunRow) {
  return {
    id: r.id,
    status: r.status,
    source: r.source,
    pocScript: r.poc_script,
    pocScriptHash: r.poc_script_hash,
    exploitProven: r.exploit_proven,
    approvedBy: r.approved_by,
    approvedAt: r.approved_at,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    durationMs: r.duration_ms,
    exitCode: r.exit_code,
    stdoutLog: r.stdout_log,
    stderrLog: r.stderr_log,
    behaviorReport: r.behavior_report,
    evidenceUrl: r.evidence_url,
    errorMessage: r.error_message,
    targetId: r.target_id,
    httpStatus: r.http_status,
    stdout: r.stdout,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    finding: {
      id: r.finding_id,
      title: r.finding_title,
      severity: r.finding_severity,
      file: r.finding_file,
      line: r.finding_line,
    },
  };
}

const POC_RUN_SELECT = `
  SELECT
    p.id, p.tenant_id, p.customer_id, p.project_id, p.finding_id,
    p.source, p.poc_script, p.poc_script_hash, p.status, p.exploit_proven,
    p.approved_by, p.approved_at, p.started_at, p.finished_at, p.duration_ms,
    p.exit_code, p.stdout_log, p.stderr_log, p.behavior_report, p.evidence_url,
    p.error_message, p.target_id, p.http_status, p.stdout, p.created_at, p.updated_at,
    f.title as finding_title, f.severity as finding_severity,
    f.file_path as finding_file, f.start_line as finding_line
  FROM poc.poc_runs p
  JOIN detection.findings f ON f.id = p.finding_id
`;

export const validationRoutes = new Hono()
  .get('/queue', async (c) => {
    const pg = c.get('pg');
    const status = c.req.query('status') ?? 'all';
    const params: unknown[] = [c.get('user').tenantId];
    let where = 'p.tenant_id = $1';
    if (status !== 'all') {
      params.push(status);
      where += ` AND p.status = $${params.length}::poc_status_enum`;
    }
    const { rows } = await pg.query(
      `${POC_RUN_SELECT}
       WHERE ${where}
       ORDER BY p.created_at DESC
       LIMIT 100`,
      params,
    );
    return c.json({ items: rows.map(rowToPocRun) });
  })

  .get('/poc/:id', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const { rows } = await pg.query(`${POC_RUN_SELECT} WHERE p.id = $2 AND p.tenant_id = $1`, [c.get('user').tenantId, id]);
    if (rows.length === 0) return c.json({ error: { code: 'not_found', message: 'PoC run not found' } }, 404);
    return c.json(rowToPocRun(rows[0]));
  })

  .post('/poc/generate', async (c) => {
    requireRole(c, PROVIDER_WRITE_ROLES);
    const body = await c.req.json().catch(() => null);
    const parsed = generateSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'Invalid body' } }, 400);
    const { findingId, capability } = parsed.data;
    const user = c.get('user');
    const pg = c.get('pg');

    const { rows: existing } = await pg.query(
      `SELECT id, status FROM poc.poc_runs
       WHERE finding_id = $1 AND tenant_id = $2
       ORDER BY created_at DESC LIMIT 1`,
      [findingId, user.tenantId],
    );
    if (existing.length > 0 && ['pending', 'approved', 'running', 'success'].includes(existing[0].status)) {
      return c.json({
        id: existing[0].id,
        status: existing[0].status,
        reused: true,
      });
    }

    let gen;
    try {
      gen = await generatePoC(findingId, user.tenantId, pg);
    } catch (e: any) {
      return c.json({ error: { code: 'not_found', message: e.message ?? 'Finding not found' } }, 404);
    }
    const finding = await pg.query(`SELECT customer_id, project_id FROM detection.findings WHERE id = $1`, [findingId]);
    if (finding.rows.length === 0) return c.json({ error: { code: 'not_found', message: 'Finding not found' } }, 404);
    const { customer_id: customerId, project_id: projectId } = finding.rows[0];

    const insert = await pg.query(
      `INSERT INTO poc.poc_runs
         (tenant_id, customer_id, project_id, finding_id, source, poc_script, poc_script_hash, status)
       VALUES ($1, $2, $3, $4, 'ai', $5, encode(sha256(convert_to($5, 'UTF8')), 'hex'), 'pending')
       RETURNING id, status, created_at`,
      [user.tenantId, customerId, projectId, findingId, gen.script],
    );
    const pocRunId = insert.rows[0].id;

    await postMessage(
      pocRunId, user.tenantId, customerId, projectId, 'assistant',
      `Generated PoC for ${gen.category} category.\n\n**Rationale**: ${gen.rationale}\n\n**Success indicators**: ${gen.successIndicators.join('; ')}\n\nReview the script and approve to run in sandbox.`,
      pg,
    );

    await recordUsageEvent({
      tenantId: user.tenantId,
      customerId,
      projectId,
      findingId,
      pocRunId,
      capability,
      provider: gen.llmProvider,
      model: gen.llmModel,
      promptTokens: gen.promptTokens,
      completionTokens: gen.completionTokens,
      costUsd: gen.costUsd,
    }, pg);

    return c.json({
      id: pocRunId,
      status: insert.rows[0].status,
      category: gen.category,
      script: gen.script,
      rationale: gen.rationale,
      successIndicators: gen.successIndicators,
      createdAt: insert.rows[0].created_at,
      usage: { promptTokens: gen.promptTokens, completionTokens: gen.completionTokens, costUsd: gen.costUsd },
    }, 201);
  })

  .post('/poc/:id/approve', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({}));
    const parsed = approveSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'Invalid body' } }, 400);
    const user = c.get('user');
    const { rows } = await pg.query(
      `UPDATE poc.poc_runs
       SET status = 'approved', approved_by = $1, approved_at = NOW(), updated_at = NOW()
       WHERE id = $2 AND tenant_id = $3 AND status = 'pending'
       RETURNING id, status, approved_at`,
      [user.id, id, user.tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found', message: 'PoC run not found or not pending' } }, 404);
    return c.json(rows[0]);
  })

  .post('/poc/:id/reject', async (c) => {
    const pg = c.get('pg');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);
    const parsed = rejectSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'reason required' } }, 400);
    const user = c.get('user');
    const { rows } = await pg.query(
      `UPDATE poc.poc_runs
       SET status = 'canceled', error_message = $1, updated_at = NOW()
       WHERE id = $2 AND tenant_id = $3 AND status IN ('pending', 'approved')
       RETURNING id, status`,
      [parsed.data.reason, id, user.tenantId],
    );
    if (rows.length === 0) return c.json({ error: { code: 'not_found', message: 'PoC run not found or not rejectable' } }, 404);
    return c.json(rows[0]);
  })

  .post('/poc/:id/execute', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const pg = c.get('pg');
    const { rows: pre } = await pg.query(
      `SELECT id, status FROM poc.poc_runs WHERE id = $1 AND tenant_id = $2`,
      [id, user.tenantId],
    );
    if (pre.length === 0) return c.json({ error: { code: 'not_found', message: 'PoC run not found' } }, 404);
    if (pre[0].status !== 'approved') {
      return c.json({ error: { code: 'bad_state', message: `PoC must be approved first (current: ${pre[0].status})` } }, 409);
    }

    const result = await executeInSandbox(id, user.tenantId);
    return c.json(result, 200);
  })

  .get('/poc/:id/chat', async (c) => {
    const id = c.req.param('id');
    const user = c.get('user');
    const messages = await listMessages(id, user.tenantId);
    return c.json({ items: messages });
  })

  .post('/poc/:id/chat', async (c) => {
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);
    const parsed = chatSchema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'message required' } }, 400);
    const user = c.get('user');
    const pg = c.get('pg');

    const { rows: pocRow } = await pg.query(
      `SELECT p.customer_id, p.project_id, p.poc_script FROM poc.poc_runs p
       WHERE p.id = $1 AND p.tenant_id = $2`,
      [id, user.tenantId],
    );
    if (pocRow.length === 0) return c.json({ error: { code: 'not_found', message: 'PoC run not found' } }, 404);
    const { customer_id: customerId, project_id: projectId, poc_script: scriptContext } = pocRow[0];

    const userMsg = await postMessage(id, user.tenantId, customerId, projectId, 'user', parsed.data.message);
    const assistantMsg = await autoAssistantReply(id, user.tenantId, customerId, projectId, parsed.data.message, scriptContext);

    return c.json({ user: userMsg, assistant: assistantMsg }, 201);
  })

  .get('/library', async (c) => {
    const pg = c.get('pg');
    const { rows } = await pg.query(
      `SELECT id, title, description, language, framework_tags, cwe_ids, reuse_count, last_reused_at, created_at
       FROM poc.poc_library
       WHERE tenant_id = $1 AND deleted_at IS NULL
       ORDER BY reuse_count DESC, created_at DESC
       LIMIT 100`,
      [c.get('user').tenantId],
    );
    return c.json({ items: rows });
  })

  .post('/library', async (c) => {
    const pg = c.get('pg');
    const user = c.get('user');
    const body = await c.req.json().catch(() => null);
    const schema = z.object({
      pocRunId: z.string().uuid(),
      title: z.string().min(1).max(200),
      description: z.string().max(1000).optional(),
      language: z.string().default('python'),
      cweIds: z.array(z.string()).default([]),
    });
    const parsed = schema.safeParse(body);
    if (!parsed.success) return c.json({ error: { code: 'bad_request', message: 'Invalid body' } }, 400);

    const { rows: pocRow } = await pg.query(
      `SELECT poc_script, poc_script_hash, customer_id, project_id FROM poc.poc_runs
       WHERE id = $1 AND tenant_id = $2 AND status IN ('success', 'failed')`,
      [parsed.data.pocRunId, user.tenantId],
    );
    if (pocRow.length === 0) return c.json({ error: { code: 'not_found', message: 'PoC run not found or not executed' } }, 404);
    const { poc_script: script, poc_script_hash: scriptHash, customer_id: customerId, project_id: projectId } = pocRow[0];

    const insert = await pg.query(
      `INSERT INTO poc.poc_library
         (tenant_id, title, description, language, framework_tags, cwe_ids, poc_script, poc_script_hash, created_by)
       VALUES ($1, $2, $3, $4, '{}', $5, $6, $7, $8)
       RETURNING id, title, created_at`,
      [user.tenantId, parsed.data.title, parsed.data.description ?? null, parsed.data.language, parsed.data.cweIds, script, scriptHash, user.id],
    );
    return c.json(insert.rows[0], 201);
  });
