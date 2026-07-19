// apps/api/src/services/poc-runner.ts
//
// Real PoC execution: shell out to apps/api/src/scripts/poc_verifier.py
// (a Python 3 script that talks to the actual target URL using
// urllib), parse its JSON verdict, and persist
// target_id / http_status / exploit_proven / stdout into
// poc.poc_runs. The previous mock was a fake "always succeeds"
// stub; this version actually exploits the target.

import { spawn } from 'child_process';
import { resolve } from 'path';
import { pool } from '../db/client';
import { recordUsageEvent } from './poc-generator';

export interface ExecutionResult {
  status: 'success' | 'failed' | 'timeout' | 'error';
  exitCode: number;
  stdoutLog: string;
  stderrLog: string;
  behaviorReport: {
    actions: string[];
    networkCalls: string[];
    filesAccessed: string[];
    durationMs: number;
  };
  exploitProven: boolean;
  evidenceSummary: string;
  httpStatus: number | null;
  targetId: string | null;
  evidenceUrl: string | null;
}

const VERIFIER_PATH = resolve(
  import.meta.dir, '..', 'scripts', 'poc_verifier.py',
);

interface VerifierJsonOut {
  family: string;
  proven: boolean;
  confidence: number;
  http_status: number | null;
  latency_ms: number;
  summary: string;
  evidence: string[];
  raw_excerpt: string;
}

async function runVerifier(spec: object, timeoutMs = 25000): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolveP, rejectP) => {
    const proc = spawn('python3', [VERIFIER_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
    let stdout = '', stderr = '';
    proc.stdout.on('data', (b) => { stdout += b.toString('utf8'); });
    proc.stderr.on('data', (b) => { stderr += b.toString('utf8'); });
    const t = setTimeout(() => {
      proc.kill('SIGKILL');
      rejectP(new Error('verifier timeout'));
    }, timeoutMs);
    proc.on('exit', (code) => {
      clearTimeout(t);
      resolveP({ exitCode: code ?? 1, stdout, stderr });
    });
    proc.on('error', (err) => {
      clearTimeout(t);
      rejectP(err);
    });
    proc.stdin.write(JSON.stringify(spec));
    proc.stdin.end();
  });
}

export async function executeInSandbox(pocRunId: string, tenantId: string): Promise<ExecutionResult> {
  const client = await pool.connect();
  let result: ExecutionResult;
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.current_tenant = '${tenantId}'`);

    // Move to running + capture start time.
    await client.query(
      `UPDATE poc.poc_runs
         SET status = 'running', started_at = NOW()
       WHERE id = $1 AND tenant_id = $2 AND status = 'approved'`,
      [pocRunId, tenantId],
    );

    // Pull the script + the related finding + target. The target
    // is either pinned on the project or the only target for the
    // customer.
    const sel = await client.query(
      `SELECT pr.poc_script, pr.finding_id, pr.project_id, pr.customer_id,
              f.title, f.cwe_ids, f.owasp_ids, f.file_path, f.start_line,
              p.id AS pid
         FROM poc.poc_runs pr
         JOIN detection.findings f ON f.id = pr.finding_id
         JOIN core.projects p ON p.id = pr.project_id
        WHERE pr.id = $1 AND pr.tenant_id = $2`,
      [pocRunId, tenantId],
    );
    if (sel.rows.length === 0) throw new Error('poc run not found');
    const row = sel.rows[0];

    // Find the target — prefer project-pinned, else latest active for customer.
    const tgt = await client.query(
      `SELECT id, base_url, auth_kind, auth_username, auth_password_ciphertext,
              auth_token_ciphertext, cookie_jar, allow_insecure
         FROM core.targets
        WHERE tenant_id = $1
          AND status != 'retired'
          AND (project_id = $2 OR customer_id = $3)
        ORDER BY (project_id = $2) DESC, last_seen_at DESC NULLS LAST, created_at DESC
        LIMIT 1`,
      [tenantId, row.pid, row.customer_id],
    );

    if (tgt.rows.length === 0) {
      result = {
        status: 'failed',
        exitCode: 1,
        stdoutLog: '',
        stderrLog: 'no target configured for this project / customer — register one at /targets first',
        behaviorReport: { actions: [], networkCalls: [], filesAccessed: [], durationMs: 0 },
        exploitProven: false,
        evidenceSummary: 'No target registered. Configure a target (POST /targets) and retry.',
        httpStatus: null,
        targetId: null,
        evidenceUrl: null,
      };
    } else {
      const t = tgt.rows[0];
      const spec = {
        target: {
          base_url: t.base_url,
          auth: t.auth_kind,
          allow_insecure: t.allow_insecure,
        },
        finding: {
          title: row.title,
          cwe: (row.cwe_ids ?? [])[0] ?? '',
          owasp: (row.owasp_ids ?? [])[0] ?? '',
          file_path: row.file_path,
          start_line: row.start_line,
        },
        evidence_hints: [],
      };

      const startedAt = Date.now();
      let exitCode = 1, stdout = '', stderr = '';
      let parsed: VerifierJsonOut | null = null;
      try {
        const r = await runVerifier(spec, 25000);
        exitCode = r.exitCode;
        stdout = r.stdout;
        stderr = r.stderr;
        try { parsed = JSON.parse(r.stdout.trim().split('\n').pop() ?? ''); } catch {}
      } catch (err: any) {
        stderr = (stderr ?? '') + '\nverifier error: ' + (err.message ?? String(err));
      }
      const durationMs = Date.now() - startedAt;

      result = {
        status: parsed?.proven ? 'success' : exitCode === 0 ? 'failed' : 'error',
        exitCode,
        stdoutLog: stdout.slice(0, 8000),
        stderrLog: stderr.slice(0, 4000),
        behaviorReport: {
          actions: parsed?.evidence ?? [],
          networkCalls: parsed?.evidence?.filter((e: string) => /^http/i.test(e)) ?? [],
          filesAccessed: [],
          durationMs,
        },
        exploitProven: !!parsed?.proven,
        evidenceSummary: parsed?.summary ?? (stderr || 'verifier returned no verdict'),
        httpStatus: parsed?.http_status ?? null,
        targetId: t.id,
        evidenceUrl: parsed?.http_status ? t.base_url : null,
      };
    }

    await client.query(
      `UPDATE poc.poc_runs
         SET status = $1,
             finished_at = NOW(),
             duration_ms = $2,
             exit_code = $3,
             stdout_log = $4,
             stderr_log = $5,
             behavior_report = $6,
             exploit_proven = $7,
             error_message = $8,
             target_id = $9,
             http_status = $10,
             evidence_url = $11
       WHERE id = $12`,
      [
        result.status === 'success' ? 'success' : result.status === 'failed' ? 'failed' : 'error',
        result.behaviorReport.durationMs,
        result.exitCode,
        result.stdoutLog,
        result.stderrLog,
        JSON.stringify(result.behaviorReport),
        result.exploitProven,
        result.status === 'error' ? result.stderrLog : null,
        result.targetId,
        result.httpStatus,
        result.evidenceUrl,
        pocRunId,
      ],
    );

    if (result.exploitProven) {
      await client.query(
        `UPDATE detection.findings
         SET status = 'confirmed', confirmed_at = NOW()
         WHERE id = $1`,
        [row.finding_id],
      );
    }

    await recordUsageEvent({
      tenantId,
      customerId: row.customer_id,
      projectId: row.pid,
      findingId: row.finding_id,
      pocRunId,
      capability: 'poc_gen',
      provider: 'python-verifier',
      model: 'security-vule-poc/1.0',
      promptTokens: 0,
      completionTokens: result.behaviorReport.durationMs,
      costUsd: 0,
    });

    await client.query('COMMIT');
  } catch (err: any) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  return result;
}