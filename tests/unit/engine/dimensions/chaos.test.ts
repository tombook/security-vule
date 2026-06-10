import { describe, expect, test } from 'bun:test';
import { ChaosDimension } from '../../../../src/engine/dimensions/chaos.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('ChaosDimension', () => {
  test('weight is 0.02', () => expect(new ChaosDimension().weight).toBe(0.02));
  test('zero path = 0', () => {
    expect(new ChaosDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('deep + branching = high risk', () => {
    expect(new ChaosDimension().compute(n({ path_depth: 5, branching_factor: 5 }), {} as CPG)).toBeGreaterThan(0.5);
  });
  test('moderate risk', () => {
    expect(new ChaosDimension().compute(n({ path_depth: 2, branching_factor: 2 }), {} as CPG)).toBeCloseTo(0.2);
  });
  test('output clamped to [0,1]', () => {
    expect(new ChaosDimension().compute(n({ path_depth: 999, branching_factor: 999 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});