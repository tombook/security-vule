/**
 * LLM Audit Logger — structured logging of every LLM call for compliance.
 *
 * Privacy: never logs code content. Only file hash, size, model, token count, cost.
 */

import { createHash } from 'crypto';
import { mkdirSync, appendFileSync, existsSync } from 'fs';
import { dirname } from 'path';

export interface AuditEntry {
  timestamp: string;
  fileHash: string;
  fileSize: number;
  language?: string;
  provider: string;
  model: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  durationMs: number;
  redactions: Array<{ type: string; count: number }>;
  injectionDetected: boolean;
  injectionRiskScore: number;
  findingsAccepted: number;
  findingsRejected: number;
  rateLimitReached: boolean;
  outcome: 'success' | 'rate_limited' | 'injection_detected' | 'no_findings';
}

export type AuditSink = {
  call: (entry: AuditEntry) => void;
};

class FileSink implements AuditSink {
  private path: string;
  constructor(path: string) {
    this.path = path;
    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  }
  call = (entry: AuditEntry): void => {
    appendFileSync(this.path, JSON.stringify(entry) + '\n');
  };
}

class StdoutSink implements AuditSink {
  call = (entry: AuditEntry): void => {
    console.log(JSON.stringify(entry));
  };
}

class MultiSink implements AuditSink {
  private sinks: AuditSink[];
  constructor(sinks: AuditSink[]) { this.sinks = sinks; }
  call = (entry: AuditEntry): void => {
    for (const s of this.sinks) {
      try { s.call(entry); } catch { /* never fail audit */ }
    }
  };
}

export class AuditLogger {
  private sink: AuditSink;
  private totalCostUsd = 0;
  private totalTokens = 0;
  private totalCalls = 0;
  private entries: AuditEntry[] = [];

  constructor(sink?: AuditSink) {
    this.sink = sink ?? new StdoutSink();
  }

  static toFile(path: string): AuditLogger {
    return new AuditLogger(new FileSink(path));
  }

  static toMulti(sinks: AuditSink[]): AuditLogger {
    return new AuditLogger(new MultiSink(sinks));
  }

  hash(content: string): string {
    return createHash('sha256').update(content).digest('hex').slice(0, 16);
  }

  record(input: Omit<AuditEntry, 'timestamp'>): void {
    const entry: AuditEntry = { timestamp: new Date().toISOString(), ...input };
    this.totalCostUsd += entry.costUsd;
    this.totalTokens += entry.totalTokens;
    this.totalCalls += 1;
    this.entries.push(entry);
    this.sink.call(entry);
  }

  summary(): { totalCostUsd: number; totalTokens: number; totalCalls: number; byProvider: Record<string, number>; byOutcome: Record<string, number> } {
    const byProvider: Record<string, number> = {};
    const byOutcome: Record<string, number> = {};
    for (const e of this.entries) {
      byProvider[e.provider] = (byProvider[e.provider] ?? 0) + 1;
      byOutcome[e.outcome] = (byOutcome[e.outcome] ?? 0) + 1;
    }
    return {
      totalCostUsd: this.totalCostUsd,
      totalTokens: this.totalTokens,
      totalCalls: this.totalCalls,
      byProvider,
      byOutcome,
    };
  }

  formatDashboard(): string {
    const s = this.summary();
    const lines: string[] = [
      `## LLM Cost Dashboard`,
      ``,
      `| Metric | Value |`,
      `|---|---|`,
      `| Total LLM calls | ${s.totalCalls} |`,
      `| Total tokens | ${s.totalTokens.toLocaleString()} |`,
      `| **Total cost** | **$${s.totalCostUsd.toFixed(4)} USD** |`,
      ``,
      `### By Provider`,
      ``,
      `| Provider | Calls |`,
      `|---|---|`,
    ];
    for (const [p, c] of Object.entries(s.byProvider)) {
      lines.push(`| ${p} | ${c} |`);
    }
    lines.push(``);
    lines.push(`### By Outcome`);
    lines.push(``);
    lines.push(`| Outcome | Calls |`);
    lines.push(`|---|---|`);
    for (const [o, c] of Object.entries(s.byOutcome)) {
      lines.push(`| ${o} | ${c} |`);
    }
    return lines.join('\n');
  }
}

export const GLOBAL_AUDIT = new AuditLogger();
