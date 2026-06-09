import { describe, expect, test } from 'bun:test';
import { RelativisticDimension } from '../../../../src/engine/dimensions/relativistic.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('RelativisticDimension', () => {
  test('weight is 0.10', () => expect(new RelativisticDimension().weight).toBe(0.10));
  test('shallow + simple = low risk', () => {
    expect(new RelativisticDimension().compute(n({ nesting_depth: 2, cyclomatic_complexity: 1 }), {} as CPG)).toBe(0.05);
  });
  test('deep nesting = high risk', () => {
    const v = new RelativisticDimension().compute(n({ nesting_depth: 10 }), {} as CPG);
    expect(v).toBeGreaterThan(0.5);
  });
  test('high cyclomatic = high risk', () => {
    expect(new RelativisticDimension().compute(n({ cyclomatic_complexity: 25 }), {} as CPG)).toBe(1);
  });
  test('boundary: depth=5 = 0, depth=6 > 0', () => {
    expect(new RelativisticDimension().compute(n({ nesting_depth: 5 }), {} as CPG)).toBe(0);
    expect(new RelativisticDimension().compute(n({ nesting_depth: 6 }), {}) as any).toBeGreaterThan(0);
  });
});