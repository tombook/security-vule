import { describe, expect, test } from 'bun:test';
import { NonEquilibriumDimension } from '../../../../src/engine/dimensions/non-equilibrium.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('NonEquilibriumDimension', () => {
  test('weight is 0.02', () => expect(new NonEquilibriumDimension().weight).toBe(0.02));
  test('zero drift = 0', () => {
    expect(new NonEquilibriumDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('high drift = high risk', () => {
    expect(new NonEquilibriumDimension().compute(n({ commit_frequency: 10, change_size: 20 }), {} as CPG)).toBeGreaterThan(0);
  });
  test('refactoring+coverage cancel risk', () => {
    expect(new NonEquilibriumDimension().compute(n({ commit_frequency: 10, change_size: 5, refactoring: 10, test_coverage: 5 }), {} as CPG)).toBe(0);
  });
  test('output clamped to [0,1]', () => {
    expect(new NonEquilibriumDimension().compute(n({ commit_frequency: 999, change_size: 999 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});