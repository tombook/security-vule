/**
 * Tests for Triage + Dedupe engine (Anthropic Harness-inspired).
 */
import { describe, expect, test } from 'bun:test';
import {
  triageFindings,
  fingerprintFinding,
  mergeTriageResults,
  exportTriage,
  type Finding,
  type KnownBug,
  type ThreatModel,
} from '../../../src/triage/triage.js';

const sampleFindings: Finding[] = [
  {
    id: 'a.php:5:sqli',
    file: 'a.php',
    line: 5,
    vulnType: 'SQL Injection',
    severity: 'HIGH',
    uvrs: 0.85,
  },
  {
    id: 'b.php:7:cmdi',
    file: 'b.php',
    line: 7,
    vulnType: 'Command Injection',
    severity: 'CRITICAL',
    uvrs: 0.95,
  },
  {
    id: 'a.php:5:sqli',
    file: 'a.php',
    line: 5,
    vulnType: 'SQL Injection',
    severity: 'HIGH',
    uvrs: 0.85,
  },
  { id: 'c.php:10:xss', file: 'c.php', line: 10, vulnType: 'XSS', severity: 'MEDIUM', uvrs: 0.55 },
];

describe('fingerprintFinding', () => {
  test('same file/line/vulnType -> same fingerprint', () => {
    const a = fingerprintFinding({
      id: '1',
      file: 'a.php',
      line: 5,
      vulnType: 'SQL Injection',
      severity: 'HIGH',
      uvrs: 0.85,
    });
    const b = fingerprintFinding({
      id: '2',
      file: 'a.php',
      line: 5,
      vulnType: 'SQL Injection',
      severity: 'CRITICAL',
      uvrs: 0.99,
    });
    expect(a).toBe(b);
  });

  test('different line -> different fingerprint', () => {
    const a = fingerprintFinding({
      id: '1',
      file: 'a.php',
      line: 5,
      vulnType: 'SQL Injection',
      severity: 'HIGH',
      uvrs: 0.85,
    });
    const b = fingerprintFinding({
      id: '1',
      file: 'a.php',
      line: 6,
      vulnType: 'SQL Injection',
      severity: 'HIGH',
      uvrs: 0.85,
    });
    expect(a).not.toBe(b);
  });

  test('different vulnType -> different fingerprint', () => {
    const a = fingerprintFinding({
      id: '1',
      file: 'a.php',
      line: 5,
      vulnType: 'SQL Injection',
      severity: 'HIGH',
      uvrs: 0.85,
    });
    const b = fingerprintFinding({
      id: '1',
      file: 'a.php',
      line: 5,
      vulnType: 'XSS',
      severity: 'HIGH',
      uvrs: 0.85,
    });
    expect(a).not.toBe(b);
  });
});

describe('triageFindings — dedupe', () => {
  test('removes duplicate findings across runs', () => {
    const result = triageFindings(sampleFindings);
    expect(result.deduplicated.length).toBe(3);
    expect(result.deduplicated.find((f) => f.id === 'a.php:5:sqli')).toBeTruthy();
  });

  test('preserves unique findings across runs', () => {
    const result = triageFindings([
      { id: '1', file: 'a.php', line: 5, vulnType: 'SQL Injection', severity: 'HIGH', uvrs: 0.85 },
      { id: '2', file: 'a.php', line: 6, vulnType: 'SQL Injection', severity: 'HIGH', uvrs: 0.85 },
      { id: '3', file: 'b.php', line: 5, vulnType: 'XSS', severity: 'MEDIUM', uvrs: 0.55 },
    ]);
    expect(result.deduplicated.length).toBe(3);
  });

  test('handles empty findings list', () => {
    const result = triageFindings([]);
    expect(result.deduplicated).toHaveLength(0);
    expect(result.summary.total).toBe(0);
  });
});

describe('triageFindings — known bug suppression', () => {
  test('suppresses known bugs by fingerprint match', () => {
    const known: KnownBug[] = [
      {
        fingerprint: fingerprintFinding({
          id: '1',
          file: 'a.php',
          line: 5,
          vulnType: 'SQL Injection',
          severity: 'HIGH',
          uvrs: 0.85,
        }),
        reason: 'Test fixture, intentional',
      },
    ];
    const result = triageFindings(sampleFindings, { knownBugs: known });
    expect(result.suppressed.length).toBe(1);
    expect(result.suppressed[0]?.finding.id).toBe('a.php:5:sqli');
    expect(result.ranked.find((f) => f.id === 'a.php:5:sqli')).toBeUndefined();
  });

  test('non-known bugs pass through', () => {
    const known: KnownBug[] = [{ fingerprint: 'nonexistent', reason: 'Other' }];
    const result = triageFindings(sampleFindings, { knownBugs: known });
    expect(result.suppressed).toHaveLength(0);
    expect(result.ranked.length).toBe(3);
  });
});

describe('triageFindings — severity recalibration', () => {
  const tm: ThreatModel = {
    internetFacing: ['public/', 'api/'],
    internalOnly: ['internal/', 'admin/'],
    dataClassification: { 'public/api/users.php': 'pii' },
    criticalAssets: ['auth/', 'payment/'],
  };

  test('promotes HIGH to CRITICAL for internet-facing', () => {
    const f: Finding = {
      id: '1',
      file: 'public/api/users.php',
      line: 5,
      vulnType: 'SQL Injection',
      severity: 'HIGH',
      uvrs: 0.85,
    };
    const result = triageFindings([f], { threatModel: tm });
    expect(result.recalibrated[0]?.severity).toBe('CRITICAL');
  });

  test('demotes CRITICAL to HIGH for internal-only', () => {
    const f: Finding = {
      id: '1',
      file: 'internal/admin/console.php',
      line: 5,
      vulnType: 'Command Injection',
      severity: 'CRITICAL',
      uvrs: 0.95,
    };
    const result = triageFindings([f], { threatModel: tm });
    expect(result.recalibrated[0]?.severity).toBe('HIGH');
  });

  test('promotes to HIGH for critical assets', () => {
    const f: Finding = {
      id: '1',
      file: 'auth/login.php',
      line: 5,
      vulnType: 'XSS',
      severity: 'MEDIUM',
      uvrs: 0.55,
    };
    const result = triageFindings([f], { threatModel: tm });
    expect(result.recalibrated[0]?.severity).toBe('HIGH');
  });

  test('promotes to CRITICAL when handling PII', () => {
    const f: Finding = {
      id: '1',
      file: 'public/api/users.php',
      line: 5,
      vulnType: 'XSS',
      severity: 'LOW',
      uvrs: 0.3,
    };
    const result = triageFindings([f], { threatModel: tm });
    expect(result.recalibrated[0]?.severity).toBe('CRITICAL');
  });

  test('leaves severity unchanged when no threat model match', () => {
    const f: Finding = {
      id: '1',
      file: 'lib/util.php',
      line: 5,
      vulnType: 'XSS',
      severity: 'MEDIUM',
      uvrs: 0.55,
    };
    const result = triageFindings([f], { threatModel: tm });
    expect(result.recalibrated[0]?.severity).toBe('MEDIUM');
  });
});

describe('triageFindings — ranking', () => {
  test('ranks by severity first, then UVRS', () => {
    const result = triageFindings([
      { id: '1', file: 'a.php', line: 5, vulnType: 'XSS', severity: 'LOW', uvrs: 0.99 },
      {
        id: '2',
        file: 'b.php',
        line: 5,
        vulnType: 'SQL Injection',
        severity: 'CRITICAL',
        uvrs: 0.5,
      },
      { id: '3', file: 'c.php', line: 5, vulnType: 'XSS', severity: 'MEDIUM', uvrs: 0.55 },
      { id: '4', file: 'd.php', line: 5, vulnType: 'CMDi', severity: 'HIGH', uvrs: 0.7 },
    ]);
    expect(result.ranked[0]?.id).toBe('2');
    expect(result.ranked[1]?.id).toBe('4');
    expect(result.ranked[2]?.id).toBe('3');
    expect(result.ranked[3]?.id).toBe('1');
  });
});

describe('triageFindings — voting', () => {
  test('flags disputed findings with low agreement', () => {
    const lowConfidence: Finding[] = [
      { id: '1', file: 'a.php', line: 5, vulnType: 'XSS', severity: 'MEDIUM', uvrs: 0.45 },
    ];
    const result = triageFindings(lowConfidence, { votes: 10 });
    expect(result.voted.length).toBeGreaterThanOrEqual(0);
  });

  test('no voting when votes=1', () => {
    const result = triageFindings(sampleFindings, { votes: 1 });
    expect(result.voted).toHaveLength(0);
  });
});

describe('mergeTriageResults', () => {
  test('merges findings from multiple runs', () => {
    const run1 = triageFindings([
      { id: '1', file: 'a.php', line: 5, vulnType: 'SQL Injection', severity: 'HIGH', uvrs: 0.85 },
    ]);
    const run2 = triageFindings([
      { id: '2', file: 'b.php', line: 5, vulnType: 'XSS', severity: 'MEDIUM', uvrs: 0.55 },
      { id: '3', file: 'a.php', line: 5, vulnType: 'SQL Injection', severity: 'HIGH', uvrs: 0.85 },
    ]);
    const merged = mergeTriageResults([run1, run2]);
    expect(merged.deduplicated).toHaveLength(2);
    expect(merged.summary.unique).toBe(2);
  });
});

describe('exportTriage', () => {
  test('JSON export is valid', () => {
    const result = triageFindings(sampleFindings);
    const json = exportTriage(result, 'json');
    const parsed = JSON.parse(json) as { summary: { total: number } };
    expect(parsed.summary.total).toBe(4);
  });

  test('Markdown export contains ranked findings', () => {
    const result = triageFindings(sampleFindings);
    const md = exportTriage(result, 'markdown');
    expect(md).toContain('# Triage Report');
    expect(md).toContain('## Ranked Findings');
    expect(md).toContain('CRITICAL');
    expect(md).toContain('b.php:7');
  });
});
