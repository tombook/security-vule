import { describe, it, expect } from 'bun:test';
import {
  VuleSandboxBridge,
  reportToMarkdown,
  DEFAULT_VERIFY_MAPPER,
  type VulnerabilityVerification,
} from '../../../src/poc/vule-sandbox-bridge.js';
import { UVRS, RiskLevel } from '../../../src/engine/uvrs.js';
import { PAYLOAD_DATABASE } from '../../../src/poc/payload-database.js';
import type { PocResult } from '../../../src/poc/sandbox.js';

function makeResult(overrides: Partial<PocResult> = {}): PocResult {
  return {
    id: 'test-1',
    success: overrides.success ?? true,
    status: overrides.status ?? 'verified',
    statusCode: overrides.statusCode ?? 200,
    responseTimeMs: overrides.responseTimeMs ?? 100,
    body: overrides.body ?? 'admin data',
    matchedExpectations: overrides.matchedExpectations ?? ['contains'],
    isolation: 'process',
    retryable: false,
    completedAt: Date.now(),
    ...overrides,
  };
}

function makeVerification(
  overrides: Partial<VulnerabilityVerification> = {}
): VulnerabilityVerification {
  return {
    id: overrides.id ?? 'test-vuln-1',
    vulnType: overrides.vulnType ?? 'error_based_sqli',
    target: overrides.target ?? 'dvwa',
    results: overrides.results ?? [makeResult()],
    verified: overrides.verified ?? true,
    confidence: overrides.confidence ?? 1.0,
    attempts: overrides.attempts ?? 1,
    successes: overrides.successes ?? 1,
    bestResult: overrides.bestResult ?? makeResult(),
  };
}

describe('VuleSandboxBridge', () => {
  describe('constructor', () => {
    it('initializes with default targets (excluding mock)', () => {
      const bridge = new VuleSandboxBridge();
      const report = bridge.generateReport();
      expect(report.totalVulns).toBe(0);
      expect(report.verificationRate).toBe(0);
    });

    it('accepts custom target list', () => {
      const bridge = new VuleSandboxBridge({ targets: ['dvwa'] });
      const report = bridge.generateReport();
      expect(report.totalVulns).toBe(0);
    });
  });

  describe('generateReport', () => {
    it('produces empty report with no verifications', () => {
      const bridge = new VuleSandboxBridge();
      const report = bridge.generateReport();
      expect(report.totalVulns).toBe(0);
      expect(report.verifiedVulns).toBe(0);
      expect(report.verificationRate).toBe(0);
      expect(report.verifications).toEqual([]);
      expect(report.uvrsDistribution).toEqual({
        [RiskLevel.LOW]: 0,
        [RiskLevel.MEDIUM]: 0,
        [RiskLevel.HIGH]: 0,
        [RiskLevel.CRITICAL]: 0,
      });
    });
  });

  describe('getStatsByType', () => {
    it('returns empty stats for no verifications', () => {
      const bridge = new VuleSandboxBridge();
      expect(bridge.getStatsByType()).toEqual({});
    });
  });

  describe('getVerification', () => {
    it('returns undefined for unknown vuln', () => {
      const bridge = new VuleSandboxBridge();
      expect(bridge.getVerification('nonexistent')).toBeUndefined();
    });
  });
});

describe('DEFAULT_VERIFY_MAPPER', () => {
  it('returns 0 for unverified vuln', () => {
    const v = makeVerification({ verified: false, confidence: 0 });
    expect(DEFAULT_VERIFY_MAPPER(v)).toBe(0);
  });

  it('returns base confidence for single verified vuln', () => {
    const v = makeVerification({ verified: true, confidence: 0.9, successes: 1 });
    const result = DEFAULT_VERIFY_MAPPER(v);
    expect(result).toBeGreaterThanOrEqual(0.9);
    expect(result).toBeLessThanOrEqual(1);
  });

  it('adds multi-hit bonus for multiple successes', () => {
    const v = makeVerification({ verified: true, confidence: 0.8, successes: 3 });
    const result = DEFAULT_VERIFY_MAPPER(v);
    expect(result).toBeGreaterThan(0.8);
  });

  it('adds cross-target bonus when results span multiple targets', () => {
    const results = [makeResult({ id: 'dvwa-sqli-low' }), makeResult({ id: 'bwapp-sqli-1' })];
    const v = makeVerification({ verified: true, confidence: 0.8, successes: 2, results });
    const result = DEFAULT_VERIFY_MAPPER(v);
    expect(result).toBeGreaterThan(0.8 + 2 * 0.05);
  });

  it('caps at 1.0', () => {
    const results = Array.from({ length: 10 }, (_, i) =>
      makeResult({ id: `dvwa-${i}`, success: true })
    );
    const results2 = Array.from({ length: 10 }, (_, i) =>
      makeResult({ id: `bwapp-${i}`, success: true })
    );
    const v = makeVerification({
      verified: true,
      confidence: 1.0,
      successes: 20,
      results: [...results, ...results2],
    });
    expect(DEFAULT_VERIFY_MAPPER(v)).toBeLessThanOrEqual(1);
  });
});

describe('UVRS integration', () => {
  it('maps verified vuln to high UVRS score', () => {
    const uvrs = new UVRS();
    const result = uvrs.compute({ verify: 1.0, consensus: 1.0 });
    expect(result.score).toBeGreaterThan(0.5);
  });

  it('maps unverified vuln to lower UVRS score than verified', () => {
    const uvrs = new UVRS();
    const unverified = uvrs.compute({ verify: 0, consensus: 0 });
    const verified = uvrs.compute({ verify: 1.0, consensus: 1.0 });
    expect(unverified.score).toBeLessThan(verified.score);
  });

  it('classify returns correct risk levels', () => {
    const uvrs = new UVRS();
    expect(uvrs.classify(0.9)).toBe(RiskLevel.CRITICAL);
    expect(uvrs.classify(0.8)).toBe(RiskLevel.HIGH);
    expect(uvrs.classify(0.6)).toBe(RiskLevel.MEDIUM);
    expect(uvrs.classify(0.1)).toBe(RiskLevel.LOW);
  });
});

describe('reportToMarkdown', () => {
  it('generates valid markdown for empty report', () => {
    const report = {
      generatedAt: '2026-06-11T00:00:00Z',
      totalVulns: 0,
      verifiedVulns: 0,
      verificationRate: 0,
      verifications: [],
      uvrsResults: new Map(),
      uvrsDistribution: {
        [RiskLevel.LOW]: 0,
        [RiskLevel.MEDIUM]: 0,
        [RiskLevel.HIGH]: 0,
        [RiskLevel.CRITICAL]: 0,
      },
    };
    const md = reportToMarkdown(report);
    expect(md).toContain('# VuleSandboxBridge Report');
    expect(md).toContain('Total vulnerabilities: 0');
    expect(md).toContain('0.0%');
  });

  it('includes verification details', () => {
    const v = makeVerification({
      id: 'dvwa-sqli-low',
      vulnType: 'error_based_sqli',
      target: 'dvwa',
    });
    const uvrsResult = new UVRS().compute({ verify: 1.0, consensus: 1.0 });
    const report = {
      generatedAt: '2026-06-11T00:00:00Z',
      totalVulns: 1,
      verifiedVulns: 1,
      verificationRate: 1.0,
      verifications: [v],
      uvrsResults: new Map([['dvwa-sqli-low', uvrsResult]]),
      uvrsDistribution: {
        [RiskLevel.LOW]: 0,
        [RiskLevel.MEDIUM]: 0,
        [RiskLevel.HIGH]: 0,
        [RiskLevel.CRITICAL]: 1,
      },
    };
    const md = reportToMarkdown(report);
    expect(md).toContain('dvwa-sqli-low');
    expect(md).toContain('error_based_sqli');
    expect(md).toContain('100.0%');
  });
});

describe('payload database coverage', () => {
  it('all entries have required fields', () => {
    for (const p of PAYLOAD_DATABASE) {
      expect(p.id).toBeTruthy();
      expect(p.target).toBeTruthy();
      expect(p.injectionType).toBeTruthy();
      expect(p.closure).toBeTruthy();
      expect(p.method).toMatch(/^(GET|POST)$/);
      expect(p.url).toBeTruthy();
      expect(p.payload).toBeTruthy();
      expect(p.category).toBeTruthy();
    }
  });

  it('has entries for all 4 targets', () => {
    const targets = new Set(PAYLOAD_DATABASE.map((p) => p.target));
    expect(targets.has('dvwa')).toBe(true);
    expect(targets.has('sqlilabs')).toBe(true);
  });
});
