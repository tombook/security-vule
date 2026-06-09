import { describe, expect, test } from 'bun:test';
import { DarkMatterDimension } from '../../../../src/engine/dimensions/dark-matter.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('DarkMatterDimension', () => {
  test('weight is 0.08', () => expect(new DarkMatterDimension().weight).toBe(0.08));
  test('no dynamic = 0', () => {
    expect(new DarkMatterDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('5 dynamic calls = 1.0', () => {
    expect(new DarkMatterDimension().compute(n({ dynamic_calls: 5 }), {} as CPG)).toBe(1);
  });
  test('reflection feature counts', () => {
    const v = new DarkMatterDimension().compute(n({ reflection: 3 }), {} as CPG);
    expect(v).toBeGreaterThan(0.5);
  });
  test('output clamped to [0,1]', () => {
    expect(new DarkMatterDimension().compute(n({ dynamic_calls: 999 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});