import { describe, expect, test } from 'bun:test';
import { EntropyDimension } from '../../../../src/engine/dimensions/entropy.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('EntropyDimension', () => {
  test('weight is 0.05', () => expect(new EntropyDimension().weight).toBe(0.05));
  test('zero entropy = 0', () => {
    expect(new EntropyDimension().compute(n(), {} as CPG)).toBe(0);
  });
  test('high halstead = high risk', () => {
    expect(new EntropyDimension().compute(n({ halstead_volume: 1500 }), {} as CPG)).toBe(1);
  });
  test('moderate halstead = partial risk', () => {
    expect(new EntropyDimension().compute(n({ halstead_volume: 500 }), {} as CPG)).toBe(0.5);
  });
  test('output clamped to [0,1]', () => {
    expect(new EntropyDimension().compute(n({ halstead_volume: 99999 }), {} as CPG)).toBeLessThanOrEqual(1);
  });
});