import { describe, expect, test } from 'bun:test';
import { PureFunctionalDimension } from '../../../../src/engine/dimensions/pure-functional.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'func', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features };
}

describe('PureFunctionalDimension', () => {
  test('weight is 0.03', () => expect(new PureFunctionalDimension().weight).toBe(0.03));
  test('pure function = 0', () => {
    expect(new PureFunctionalDimension().compute(n({ loc: 10 }), {} as CPG)).toBe(0);
  });
  test('impure function = high risk', () => {
    const v = new PureFunctionalDimension().compute(n({ mutable_vars: 5, side_effects: 3, loc: 10 }), {} as CPG);
    expect(v).toBeGreaterThan(0.3);
  });
  test('only mutations = partial risk', () => {
    const v = new PureFunctionalDimension().compute(n({ mutable_vars: 4, loc: 10 }), {} as CPG);
    expect(v).toBeCloseTo(0.2);
  });
  test('output clamped to [0,1]', () => {
    expect(new PureFunctionalDimension().compute(n({ mutable_vars: 999, side_effects: 999, loc: 1 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});