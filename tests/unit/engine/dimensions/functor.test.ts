import { describe, expect, test } from 'bun:test';
import { FunctorDimension } from '../../../../src/engine/dimensions/functor.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(id = 'x'): CPGNode {
  return { id, type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} };
}

describe('FunctorDimension', () => {
  test('weight is 0.03', () => expect(new FunctorDimension().weight).toBe(0.03));
  test('no verdicts = 0', () => {
    expect(new FunctorDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('matching verdicts = 0', () => {
    const d = new FunctorDimension();
    d.setVerdicts({ x: [0.5, 0.5] });
    expect(d.compute(n(), {} as CPG)).toBe(0);
  });
  test('mismatched verdicts = high risk', () => {
    const d = new FunctorDimension();
    d.setVerdicts({ x: [0.1, 0.9] });
    expect(d.compute(n(), {} as CPG)).toBeCloseTo(0.8);
  });
  test('max disagreement = 1', () => {
    const d = new FunctorDimension();
    d.setVerdicts({ x: [0, 1] });
    expect(d.compute(n(), {} as CPG)).toBe(1);
  });
});