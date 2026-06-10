import { describe, expect, test } from 'bun:test';
import { DIMENSIONS, normalizeWeights } from '../../../../src/engine/dimensions/registry.js';

describe('Math frameworks integration', () => {
  test('all 6 math framework dimensions registered', () => {
    for (const n of ['typeTheory', 'functor', 'tda', 'pureFunctional', 'abstractInterpret', 'symbolicExec']) {
      expect(DIMENSIONS[n]).toBeDefined();
    }
  });
  test('total dimensions = 19 (13 cosmic + 6 frameworks)', () => {
    expect(Object.keys(DIMENSIONS).length).toBe(19);
  });
  test('total weights normalize to 1.0', () => {
    const raw: Record<string, number> = {};
    for (const [k, d] of Object.entries(DIMENSIONS)) raw[k] = d.weight;
    const norm = normalizeWeights(raw);
    const sum = Object.values(norm).reduce((s, w) => s + w, 0);
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
  });
  test('all weights sum to 1.36+ (before normalization)', () => {
    const sum = Object.values(DIMENSIONS).reduce((s, d) => s + d.weight, 0);
    // Each weight was assigned independently; total > 1 is expected before normalize
    expect(sum).toBeGreaterThan(1.0);
  });
});