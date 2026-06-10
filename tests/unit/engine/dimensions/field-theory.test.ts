import { describe, expect, test } from 'bun:test';
import { FieldTheoryDimension } from '../../../../src/engine/dimensions/field-theory.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('FieldTheoryDimension', () => {
  test('weight is 0.02', () => expect(new FieldTheoryDimension().weight).toBe(0.02));
  test('balanced = 0', () => {
    expect(new FieldTheoryDimension().compute(n({ assignments: 5, cyclomatic_complexity: 5 }), {} as CPG)).toBe(0);
  });
  test('imbalanced = high risk', () => {
    expect(new FieldTheoryDimension().compute(n({ assignments: 20 }), {} as CPG)).toBe(1);
  });
  test('output clamped to [0,1]', () => {
    expect(new FieldTheoryDimension().compute(n({ assignments: 999, cyclomatic_complexity: 999 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
  test('moderate imbalance = partial', () => {
    expect(new FieldTheoryDimension().compute(n({ assignments: 10, cyclomatic_complexity: 0 }), {} as CPG)).toBe(0.5);
  });
});