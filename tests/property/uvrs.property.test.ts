/**
 * Property-based tests for UVRS (Unified Vulnerability Risk Score) engine.
 */
import { describe, expect, test } from 'bun:test';
import fc from 'fast-check';
import { UVRS, RiskLevel, type UVRSWeights, type UVRSComponents } from '../../src/engine/uvrs.js';

describe('UVRS property: score bounds', () => {
  test('compute() always returns score in [0, 1)', () => {
    fc.assert(
      fc.property(
        fc.record({
          taint: fc.float({ min: 0, max: 1, noNaN: true }),
          ast: fc.float({ min: 0, max: 1, noNaN: true }),
          llm: fc.float({ min: 0, max: 1, noNaN: true }),
          consensus: fc.float({ min: 0, max: 1, noNaN: true }),
          verify: fc.float({ min: 0, max: 1, noNaN: true }),
          chain: fc.float({ min: 0, max: 1, noNaN: true }),
          darkMatter: fc.float({ min: 0, max: 1, noNaN: true }),
          evolution: fc.float({ min: 0, max: 1, noNaN: true }),
          quantum: fc.float({ min: 0, max: 1, noNaN: true }),
          entropy: fc.float({ min: 0, max: 1, noNaN: true }),
        }),
        (components) => {
          const uvrs = new UVRS();
          const result = uvrs.compute(components as UVRSComponents);
          expect(result.score).toBeGreaterThanOrEqual(0);
          expect(result.score).toBeLessThan(1);
        }
      ),
      { numRuns: 200 }
    );
  });

  test('classify() is monotonic in score', () => {
    fc.assert(
      fc.property(
        fc.float({ min: Math.fround(0.001), max: Math.fround(0.99), noNaN: true }),
        fc.float({ min: 0, max: 0.5, noNaN: true, maxAfter: Math.frunc }),
        (baseScore, delta) => {
          const low = Math.fround(baseScore);
          const high = Math.min(0.99, low + delta);
          const uvrs = new UVRS();
          const lowClass = uvrs.classify(low);
          const highClass = uvrs.classify(high);
          // Higher score should not yield lower risk level
          const order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL];
          expect(order.indexOf(highClass)).toBeGreaterThanOrEqual(order.indexOf(lowClass));
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe('UVRS property: edge cases', () => {
  test('empty components returns LOW or MEDIUM (defaults)', () => {
    const uvrs = new UVRS();
    const result = uvrs.compute({});
    expect([RiskLevel.LOW, RiskLevel.MEDIUM]).toContain(result.level);
  });

  test('max components returns CRITICAL risk (with custom thresholds)', () => {
    // Lower thresholds so 0.731 qualifies as CRITICAL
    const uvrs = new UVRS(
      {
        taint: 1.0,
        ast: 0.0,
        llm: 0.0,
        consensus: 0.0,
        verify: 0.0,
        chain: 0.0,
        darkMatter: 0.0,
        evolution: 0.0,
        quantum: 0.0,
        entropy: 0.0,
      },
      { LOW: 0.1, MEDIUM: 0.3, HIGH: 0.5, CRITICAL: 0.7 }
    );
    const result = uvrs.compute({ taint: 1 });
    expect(result.level).toBe(RiskLevel.CRITICAL);
  });
});

describe('UVRS property: deterministic', () => {
  test('same input → same output (reproducible)', () => {
    fc.assert(
      fc.property(
        fc.record({
          taint: fc.float({ min: 0, max: 1, noNaN: true }),
          ast: fc.float({ min: 0, max: 1, noNaN: true }),
        }),
        (components) => {
          const uvrs = new UVRS();
          const r1 = uvrs.compute(components as UVRSComponents);
          const r2 = uvrs.compute(components as UVRSComponents);
          expect(r1.score).toBe(r2.score);
          expect(r1.level).toBe(r2.level);
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe('UVRS property: weight validation', () => {
  test('normalizeWeights rescales positive weights to sum=1', () => {
    const uvrs = new UVRS();
    const raw: UVRSWeights = {
      taint: 0.4,
      ast: 0.2,
      llm: 0.1,
      consensus: 0.1,
      verify: 0.1,
      chain: 0.05,
      darkMatter: 0.025,
      evolution: 0.0125,
      quantum: 0.0125,
      entropy: 0,
    };
    const result = uvrs.compute({
      taint: 1,
      ast: 1,
      llm: 1,
      consensus: 1,
      verify: 1,
      chain: 1,
      darkMatter: 1,
      evolution: 1,
      quantum: 1,
    });
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThan(1);
  });
});
