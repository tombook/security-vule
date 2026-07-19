// apps/api/src/services/scan/scheduler.ts
// P3.3 调度器:SLA 优先级 + 客户隔离 + 并发限流(in-memory,生产可换 Redis)

import { EventEmitter } from 'node:events';
import { pool } from '../../db/client';
import { runAllEngines, dedupeFindings, EngineResult } from './engines';

export interface ScanJob {
  scanId: string;
  tenantId: string;
  customerId: string;
  projectId: string;
  projectPath: string;
  priority: number;
  enqueuedAt: number;
}

export interface ScanProgress {
  scanId: string;
  stage: 'queued' | 'pulling' | 'analyzing' | 'done' | 'partial' | 'failed' | 'canceled';
  percent: number;
  engineResults: EngineResult[];
  startedAt: number;
  finishedAt?: number;
  errorMessage?: string;
}

class ScanScheduler extends EventEmitter {
  private queue: ScanJob[] = [];
  private running = new Map<string, ScanJob>();
  private progress = new Map<string, ScanProgress>();
  private concurrentByTenant = new Map<string, number>();
  private maxConcurrentPerTenant = 2;
  private maxConcurrentGlobal = 4;
  private isProcessing = false;
  private canceled = new Set<string>();

  enqueue(job: ScanJob): void {
    this.queue.push(job);
    this.queue.sort((a, b) => b.priority - a.priority);
    this.emit('enqueued', job);
    void this.tryProcess();
  }

  cancel(scanId: string): boolean {
    const idx = this.queue.findIndex((j) => j.scanId === scanId);
    if (idx >= 0) {
      this.queue.splice(idx, 1);
      this.emit('canceled', scanId);
      return true;
    }
    if (this.running.has(scanId)) {
      this.canceled.add(scanId);
      this.emit('canceling', scanId);
      return true;
    }
    return false;
  }

  getProgress(scanId: string): ScanProgress | undefined {
    return this.progress.get(scanId);
  }

  getQueueDepth(): { queued: number; running: number } {
    return { queued: this.queue.length, running: this.running.size };
  }

  private async tryProcess(): Promise<void> {
    if (this.isProcessing) return;
    this.isProcessing = true;
    try {
      while (this.running.size < this.maxConcurrentGlobal) {
        const job = this.takeNext();
        if (!job) break;
        this.running.set(job.scanId, job);
        this.concurrentByTenant.set(job.tenantId, (this.concurrentByTenant.get(job.tenantId) ?? 0) + 1);
        this.progress.set(job.scanId, {
          scanId: job.scanId, stage: 'queued', percent: 0, engineResults: [], startedAt: Date.now(),
        });
        this.updateScanStatus(job.scanId, 'running', null).catch(() => {});
        void this.runJob(job).finally(() => {
          this.running.delete(job.scanId);
          this.concurrentByTenant.set(job.tenantId, (this.concurrentByTenant.get(job.tenantId) ?? 0) - 1);
        });
      }
    } finally {
      this.isProcessing = false;
    }
  }

  private takeNext(): ScanJob | null {
    for (let i = 0; i < this.queue.length; i++) {
      const job = this.queue[i];
      const running = this.concurrentByTenant.get(job.tenantId) ?? 0;
      if (running < this.maxConcurrentPerTenant) {
        this.queue.splice(i, 1);
        return job;
      }
    }
    return null;
  }

  private async runJob(job: ScanJob): Promise<void> {
    try {
      if (this.canceled.has(job.scanId)) {
        await this.updateScanStatus(job.scanId, 'canceled', null);
        return;
      }
      this.updateProgress(job.scanId, { stage: 'pulling', percent: 10 });

      const results = await runAllEngines(job.projectPath);
      if (this.canceled.has(job.scanId)) {
        await this.updateScanStatus(job.scanId, 'canceled', null);
        return;
      }

      this.updateProgress(job.scanId, {
        stage: 'analyzing',
        percent: 60,
        engineResults: results,
      });

      const findings = dedupeFindings(results);
      await this.persistFindings(job, findings);

      const anyFailed = results.some((r) => r.status === 'failed' || r.status === 'timeout');
      const anySuccess = results.some((r) => r.status === 'success' || r.status === 'partial');
      const finalStatus = anyFailed && !anySuccess ? 'failed'
        : anyFailed ? 'partial'
        : 'done';
      const totalDuration = results.reduce((s, r) => s + r.durationMs, 0);

      await this.updateScanStatus(job.scanId, finalStatus, totalDuration, findings.length);

      this.updateProgress(job.scanId, {
        stage: finalStatus,
        percent: 100,
        engineResults: results,
        finishedAt: Date.now(),
      });
    } catch (err: any) {
      await this.updateScanStatus(job.scanId, 'failed', null, 0, err.message).catch(() => {});
      this.updateProgress(job.scanId, {
        stage: 'failed', percent: 100, engineResults: [], finishedAt: Date.now(),
        errorMessage: err.message,
      });
    } finally {
      this.canceled.delete(job.scanId);
      this.emit('done', job.scanId);
      void this.tryProcess();
    }
  }

  private updateProgress(scanId: string, partial: Partial<ScanProgress>): void {
    const cur = this.progress.get(scanId);
    if (cur) {
      this.progress.set(scanId, { ...cur, ...partial });
      this.emit('progress', this.progress.get(scanId));
    }
  }

  private async updateScanStatus(scanId: string, status: string, durationMs: number | null, findingsTotal = 0, errorMessage?: string): Promise<void> {
    const setClauses = ['status = $1::scan_status_enum', 'findings_total = $2'];
    const params: unknown[] = [status, findingsTotal];
    if (status === 'done' || status === 'partial' || status === 'failed' || status === 'canceled') {
      setClauses.push('finished_at = NOW()');
    }
    if (durationMs !== null) {
      setClauses.push(`duration_ms = $${params.push(durationMs)}`);
    }
    if (errorMessage) {
      setClauses.push(`error_message = $${params.push(errorMessage)}`);
    }
    params.push(scanId);
    await pool.query(
      `UPDATE detection.scan_runs SET ${setClauses.join(', ')} WHERE id = $${params.length}`,
      params,
    );
  }

  private async persistFindings(job: ScanJob, findings: ReturnType<typeof dedupeFindings>): Promise<void> {
    if (!findings.length) return;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL app.current_tenant = '${job.tenantId}'`);
      await client.query(`SET LOCAL app.current_user_role = 'SystemBot'`);
      for (const f of findings) {
        const fingerprint = require('node:crypto').createHash('sha256')
          .update(`${f.rule_id}|${f.file_path}|${f.start_line}`).digest('hex').slice(0, 32);
        await client.query(
          `INSERT INTO detection.findings
             (tenant_id, customer_id, project_id, scan_run_id, snapshot_id, rule_id,
              fingerprint, severity, status, title, description, file_path,
              start_line, end_line, code_snippet, cwe_ids, owasp_ids, confidence, engines, first_seen_at, last_seen_at)
           SELECT $1, $2, $3, $4,
                  (SELECT snapshot_id FROM detection.scan_runs WHERE id = $4),
                  COALESCE((SELECT id FROM detection.rules WHERE rule_external_id = $5 LIMIT 1),
                           (SELECT id FROM detection.rules LIMIT 1)),
                  $6, $7::severity_enum, 'open', $8, $9, $10, $11, $12, $13, $14, $15, $16::confidence_enum, ARRAY[$17], NOW(), NOW()
           ON CONFLICT (tenant_id, fingerprint, (snapshot_id)) DO NOTHING`,
          [job.tenantId, job.customerId, job.projectId, job.scanId, f.rule_id, fingerprint,
           f.severity, f.title, f.description ?? '', f.file_path, f.start_line, f.end_line ?? f.start_line,
           f.code_snippet ?? '', f.cwe_ids ?? [], f.owasp_ids ?? [], f.confidence ?? 'medium', f.engine],
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }
}

export const scanScheduler = new ScanScheduler();

export function computeJobPriority(slaTier: string, triggerType: string): number {
  let p = 50;
  if (slaTier === 'enterprise') p += 40;
  else if (slaTier === 'priority') p += 25;
  else p += 10;
  if (triggerType === 'manual') p += 30;
  else if (triggerType === 'ci') p += 20;
  return p;
}