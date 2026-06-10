import { describe, expect, test } from 'bun:test';
import { TypeTheoryDimension } from '../../../../src/engine/dimensions/type-theory.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features };
}

describe('TypeTheoryDimension', () => {
  test('weight is 0.03', () => expect(new TypeTheoryDimension().weight).toBe(0.03));
  test('zero violations = 0 risk', () => {
    expect(new TypeTheoryDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('many `any` = high risk', () => {
    expect(new TypeTheoryDimension().compute(n({ any_count: 5, loc: 10 }), {} as CPG)).toBe(1);
  });
  test('moderate any = partial risk', () => {
    expect(new TypeTheoryDimension().compute(n({ any_count: 1, loc: 10 }), {} as CPG)).toBe(0.2);
  });
  test('cast counts (less weight than any)', () => {
    expect(new TypeTheoryDimension().compute(n({ cast_count: 5, loc: 10 }), {} as CPG)).toBe(0.5);
  });
  test('output clamped to [0,1]', () => {
    expect(new TypeTheoryDimension().compute(n({ any_count: 9999, loc: 1 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});