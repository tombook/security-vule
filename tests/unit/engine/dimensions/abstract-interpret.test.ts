import { describe, expect, test } from 'bun:test';
import { AbstractInterpretDimension } from '../../../../src/engine/dimensions/abstract-interpret.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features };
}

describe('AbstractInterpretDimension', () => {
  test('weight is 0.03', () => expect(new AbstractInterpretDimension().weight).toBe(0.03));
  test('no ranges = 0', () => {
    expect(new AbstractInterpretDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('large ranges = high risk', () => {
    expect(new AbstractInterpretDimension().compute(n({ taint_max: 5, value_range: 5 }), {} as CPG)).toBe(1);
  });
  test('taint_max alone contributes', () => {
    expect(new AbstractInterpretDimension().compute(n({ taint_max: 10 }), {} as CPG)).toBe(1);
  });
  test('moderate range = partial', () => {
    expect(new AbstractInterpretDimension().compute(n({ taint_max: 2, value_range: 3 }), {} as CPG)).toBe(0.5);
  });
});