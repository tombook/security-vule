/**
 * Unified AI Security Metrics Report.
 *
 * Aggregates findings from: prompt-injection detection, secret redaction,
 * validation rejection, rate limiter, audit logger.
 * Produces a single Markdown report for compliance review.
 */

import type { AuditEntry } from './audit.js';

export interface SecurityMetrics {
  totalScans: number;
  totalInjectionAttempts: number;
  totalInjectionsBlocked: number;
  totalSecretsRedacted: number;
  totalFindingsAccepted: number;
  totalFindingsRejected: number;
  totalRateLimitHits: number;
  totalCostUsd: number;
  uniqueInjectionPatterns: Map<string, number>;
  uniqueSecretTypes: Map<string, number>;
  injectionToFindingRatio: number;
  rejectionRate: number;
}

export function computeMetrics(entries: AuditEntry[]): SecurityMetrics {
  const m: SecurityMetrics = {
    totalScans: entries.length,
    totalInjectionAttempts: 0,
    totalInjectionsBlocked: 0,
    totalSecretsRedacted: 0,
    totalFindingsAccepted: 0,
    totalFindingsRejected: 0,
    totalRateLimitHits: 0,
    totalCostUsd: 0,
    uniqueInjectionPatterns: new Map(),
    uniqueSecretTypes: new Map(),
    injectionToFindingRatio: 0,
    rejectionRate: 0,
  };
  for (const e of entries) {
    m.totalCostUsd += e.costUsd;
    m.totalFindingsAccepted += e.findingsAccepted;
    m.totalFindingsRejected += e.findingsRejected;
    if (e.injectionDetected) m.totalInjectionAttempts++;
    for (const r of e.redactions) {
      m.totalSecretsRedacted += r.count;
      m.uniqueSecretTypes.set(r.type, (m.uniqueSecretTypes.get(r.type) ?? 0) + r.count);
    }
    if (e.outcome === 'rate_limited' || e.rateLimitReached) m.totalRateLimitHits++;
  }
  m.injectionToFindingRatio = m.totalInjectionAttempts > 0 ? m.totalFindingsAccepted / m.totalInjectionAttempts : 0;
  const totalFindings = m.totalFindingsAccepted + m.totalFindingsRejected;
  m.rejectionRate = totalFindings > 0 ? m.totalFindingsRejected / totalFindings : 0;
  m.totalInjectionsBlocked = m.totalInjectionAttempts;
  return m;
}

export function formatMetricsReport(m: SecurityMetrics): string {
  const lines: string[] = [
    `# security-vule AI Security Metrics Report`,
    ``,
    `> Generated automatically from audit log. Use to track AI security posture over time.`,
    ``,
    `## Summary`,
    ``,
    `| Metric | Value |`,
    `|---|---|`,
    `| Total LLM scans | ${m.totalScans} |`,
    `| **Total injection attempts detected** | **${m.totalInjectionAttempts}** |`,
    `| **Total secrets redacted** | **${m.totalSecretsRedacted}** |`,
    `| Total findings accepted | ${m.totalFindingsAccepted} |`,
    `| Total findings rejected by sanity check | ${m.totalFindingsRejected} |`,
    `| **Rejection rate** | **${(m.rejectionRate * 100).toFixed(1)}%** |`,
    `| Rate limit hits | ${m.totalRateLimitHits} |`,
    `| **Total LLM cost** | **$${m.totalCostUsd.toFixed(4)}** |`,
    ``,
    `## Injection Attempts by Risk Pattern`,
    ``,
  ];
  if (m.uniqueInjectionPatterns.size === 0) {
    lines.push(`_No injection attempts detected._`);
  } else {
    lines.push(`| Pattern | Count |`);
    lines.push(`|---|---|`);
    const sorted = [...m.uniqueInjectionPatterns.entries()].sort((a, b) => b[1] - a[1]);
    for (const [p, c] of sorted) {
      lines.push(`| \`${p}\` | ${c} |`);
    }
  }
  lines.push(``);
  lines.push(`## Secret Types Redacted`);
  lines.push(``);
  if (m.uniqueSecretTypes.size === 0) {
    lines.push(`_No secrets redacted._`);
  } else {
    lines.push(`| Secret type | Count |`);
    lines.push(`|---|---|`);
    const sorted = [...m.uniqueSecretTypes.entries()].sort((a, b) => b[1] - a[1]);
    for (const [t, c] of sorted) {
      lines.push(`| ${t} | ${c} |`);
    }
  }
  lines.push(``);
  lines.push(`## Risk Assessment`);
  lines.push(``);
  const risk = m.totalInjectionAttempts > m.totalScans * 0.1 ? 'HIGH' : m.totalInjectionAttempts > 0 ? 'MEDIUM' : 'LOW';
  lines.push(`Overall AI security risk: **${risk}**`);
  if (risk === 'HIGH') {
    lines.push(``);
    lines.push(`> ⚠️ Injection attempts exceed 10% of scans. Consider:`);
    lines.push(`> - Reviewing scanned code sources`);
    lines.push(`> - Tightening pre-acceptance code review`);
    lines.push(`> - Increasing rate limits if false positives`);
  }
  return lines.join('\n');
}
