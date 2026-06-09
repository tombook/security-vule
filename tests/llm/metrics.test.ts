import { describe, it, expect } from 'bun:test';
import { computeMetrics, formatMetricsReport } from '../../src/llm/metrics';
import type { AuditEntry } from '../../src/llm/audit';

const entry = (overrides: Partial<AuditEntry>): AuditEntry => ({
  timestamp: '2026-01-01T00:00:00Z',
  fileHash: 'abc',
  fileSize: 100,
  provider: 'zhipu',
  model: 'glm-5.1',
  promptTokens: 100,
  completionTokens: 50,
  totalTokens: 150,
  costUsd: 0.01,
  durationMs: 100,
  redactions: [],
  injectionDetected: false,
  injectionRiskScore: 0,
  findingsAccepted: 0,
  findingsRejected: 0,
  rateLimitReached: false,
  outcome: 'success',
  ...overrides,
});

describe('computeMetrics', () => {
  it('returns zeros for empty entries', () => {
    const m = computeMetrics([]);
    expect(m.totalScans).toBe(0);
    expect(m.totalCostUsd).toBe(0);
    expect(m.injectionToFindingRatio).toBe(0);
  });

  it('aggregates cost across entries', () => {
    const m = computeMetrics([
      entry({ costUsd: 0.01 }),
      entry({ costUsd: 0.02 }),
      entry({ costUsd: 0.005 }),
    ]);
    expect(m.totalCostUsd).toBeCloseTo(0.035, 6);
  });

  it('counts injection attempts', () => {
    const m = computeMetrics([
      entry({ injectionDetected: true }),
      entry({ injectionDetected: true }),
      entry({ injectionDetected: false }),
    ]);
    expect(m.totalInjectionAttempts).toBe(2);
  });

  it('sums redactions by type', () => {
    const m = computeMetrics([
      entry({ redactions: [{ type: 'AWS Access Key', count: 2 }, { type: 'GitHub Token', count: 1 }] }),
      entry({ redactions: [{ type: 'AWS Access Key', count: 1 }] }),
    ]);
    expect(m.totalSecretsRedacted).toBe(4);
    expect(m.uniqueSecretTypes.get('AWS Access Key')).toBe(3);
    expect(m.uniqueSecretTypes.get('GitHub Token')).toBe(1);
  });

  it('computes rejection rate', () => {
    const m = computeMetrics([
      entry({ findingsAccepted: 3, findingsRejected: 1 }),
      entry({ findingsAccepted: 2, findingsRejected: 2 }),
    ]);
    expect(m.rejectionRate).toBeCloseTo(0.375, 3);
  });

  it('counts rate limit hits', () => {
    const m = computeMetrics([
      entry({ rateLimitReached: true, outcome: 'rate_limited' }),
      entry({ rateLimitReached: false }),
    ]);
    expect(m.totalRateLimitHits).toBe(1);
  });
});

describe('formatMetricsReport', () => {
  it('includes all summary metrics', () => {
    const m = computeMetrics([entry({ costUsd: 0.5, injectionDetected: true })]);
    const out = formatMetricsReport(m);
    expect(out).toContain('AI Security Metrics Report');
    expect(out).toContain('Total LLM scans');
    expect(out).toContain('Total injection attempts detected');
    expect(out).toContain('Total secrets redacted');
    expect(out).toContain('Rejection rate');
    expect(out).toContain('Total LLM cost');
  });

  it('shows HIGH risk when injection rate > 10%', () => {
    const entries: AuditEntry[] = [];
    for (let i = 0; i < 5; i++) entries.push(entry({ injectionDetected: true }));
    for (let i = 0; i < 5; i++) entries.push(entry({ injectionDetected: false }));
    const m = computeMetrics(entries);
    const out = formatMetricsReport(m);
    expect(out).toContain('HIGH');
  });

  it('shows LOW risk when no injections', () => {
    const m = computeMetrics([entry({})]);
    const out = formatMetricsReport(m);
    expect(out).toContain('LOW');
  });

  it('lists redacted secret types in descending order', () => {
    const m = computeMetrics([
      entry({ redactions: [{ type: 'Generic JWT', count: 1 }] }),
      entry({ redactions: [{ type: 'AWS Access Key', count: 5 }] }),
    ]);
    const out = formatMetricsReport(m);
    const awsIdx = out.indexOf('AWS Access Key');
    const jwtIdx = out.indexOf('Generic JWT');
    expect(awsIdx).toBeGreaterThan(-1);
    expect(jwtIdx).toBeGreaterThan(-1);
    expect(awsIdx).toBeLessThan(jwtIdx);
  });

  it('handles empty case gracefully', () => {
    const m = computeMetrics([]);
    const out = formatMetricsReport(m);
    expect(out).toContain('_No injection attempts detected._');
    expect(out).toContain('_No secrets redacted._');
  });
});
