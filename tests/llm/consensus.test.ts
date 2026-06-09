import { describe, it, expect } from 'bun:test';
import { findMatch, formatConsensusReport } from '../../src/llm/consensus';
import type { VulnerabilityFinding } from '../../src/detection/llm-agent';

const f = (overrides: Partial<VulnerabilityFinding>): VulnerabilityFinding => ({
  type: 'SQL Injection',
  severity: 'high',
  line: 5,
  description: 'Test description that is long enough to pass validation rules',
  remediation: 'Test remediation that is long enough to pass validation rules',
  codeSnippet: '$query = "SELECT " . $x;',
  confidence: 0.8,
  ...overrides,
});

describe('findMatch', () => {
  it('matches same type and same line', () => {
    const a = f({ line: 5 });
    const b = f({ line: 5 });
    expect(findMatch(a, [b])).toBe(b);
  });

  it('matches same type within 3-line tolerance', () => {
    const a = f({ line: 5 });
    const b = f({ line: 7 });
    expect(findMatch(a, [b])).toBe(b);
  });

  it('does not match same type beyond 3-line tolerance', () => {
    const a = f({ line: 5 });
    const b = f({ line: 10 });
    expect(findMatch(a, [b])).toBeUndefined();
  });

  it('does not match different type same line', () => {
    const a = f({ type: 'SQL Injection', line: 5 });
    const b = f({ type: 'Command Injection', line: 5 });
    expect(findMatch(a, [b])).toBeUndefined();
  });

  it('normalizes type names for matching', () => {
    const a = f({ type: 'SQL Injection', line: 5 });
    const b = f({ type: 'SQL injection', line: 5 });
    expect(findMatch(a, [b])).toBe(b);
  });

  it('returns first match when multiple candidates', () => {
    const a = f({ line: 5 });
    const b1 = f({ line: 5 });
    const b2 = f({ line: 5 });
    expect(findMatch(a, [b1, b2])).toBe(b1);
  });

  it('returns undefined on empty candidates', () => {
    expect(findMatch(f({}), [])).toBeUndefined();
  });
});

describe('formatConsensusReport', () => {
  it('formats a report with confirmed findings', () => {
    const r = {
      confirmed: [f({ line: 5, severity: 'critical', type: 'SQL Injection' })],
      disputed: [],
      rejected: [],
      onlyA: [],
      onlyB: [],
      stats: { aTotal: 1, bTotal: 1, confirmedCount: 1, disputedCount: 0, matchRate: 1.0 },
    };
    const out = formatConsensusReport(r);
    expect(out).toContain('Confirmed (both models agree)');
    expect(out).toContain('SQL Injection');
    expect(out).toContain('line 5');
    expect(out).toContain('Match rate: 100.0%');
  });

  it('formats a report with disputed findings', () => {
    const r = {
      confirmed: [],
      disputed: [{
        status: 'disputed' as const,
        findingA: f({ severity: 'critical' }),
        findingB: f({ severity: 'low' }),
        reason: 'severity mismatch',
      }],
      rejected: [],
      onlyA: [],
      onlyB: [],
      stats: { aTotal: 1, bTotal: 1, confirmedCount: 0, disputedCount: 1, matchRate: 0 },
    };
    const out = formatConsensusReport(r);
    expect(out).toContain('Disputed');
    expect(out).toContain('severity mismatch');
  });

  it('formats a report with only-A and only-B findings', () => {
    const r = {
      confirmed: [],
      disputed: [],
      rejected: [],
      onlyA: [{ status: 'only-a' as const, findingA: f({}), reason: 'A only' }],
      onlyB: [{ status: 'only-b' as const, findingB: f({}), reason: 'B only' }],
      stats: { aTotal: 1, bTotal: 1, confirmedCount: 0, disputedCount: 0, matchRate: 0 },
    };
    const out = formatConsensusReport(r);
    expect(out).toContain('Only Model A');
    expect(out).toContain('Only Model B');
  });
});
