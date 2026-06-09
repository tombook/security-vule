import { describe, expect, test } from 'bun:test';
import { PerturbationDimension } from '../../../../src/engine/dimensions/perturbation.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('PerturbationDimension', () => {
  test('weight is 0.05', () => expect(new PerturbationDimension().weight).toBe(0.05));
  test('zero churn = zero risk', () => {
    expect(new PerturbationDimension().compute(n({ complexity: 5 }), {} as CPG)).toBe(0);
  });
  test('high churn + high complexity = high risk', () => {
    expect(new PerturbationDimension().compute(n({ churn: 1000, complexity: 10 }), {} as CPG)).toBe(1);
  });
  test('medium values = partial risk', () => {
    const v = new PerturbationDimension().compute(n({ churn: 50, complexity: 5 }), {} as CPG);
    expect(v).toBeGreaterThan(0);
    expect(v).toBeLessThan(1);
  });
  test('output clamped to [0,1]', () => {
    const v = new PerturbationDimension().compute(n({ churn: 999999, complexity: 999 }), {} as CPG);
    expect(v).toBeLessThanOrEqual(1);
  });
});