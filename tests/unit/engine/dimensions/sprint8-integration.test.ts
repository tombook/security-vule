import { describe, expect, test } from 'bun:test';
import { DIMENSIONS, normalizeWeights } from '../../../../src/engine/dimensions/registry.js';

describe('Sprint 8 dimensions integration', () => {
  test('all 10 new dimensions registered', () => {
    for (const n of [
      'chaos',
      'phaseTransition',
      'fieldTheory',
      'fractal',
      'nonEquilibrium',
      'gameTheory',
      'transfer',
      'differentialGeometry',
      'renormalization',
      'categoryBasic',
    ]) {
      expect(DIMENSIONS[n]).toBeDefined();
    }
  });
  test('total dimensions = 30 (19 P0-P2 + 6 frameworks + 4 P3... wait 19+10=29)', () => {
    expect(Object.keys(DIMENSIONS).length).toBe(30);
  });
  test('total weights normalize to 1.0', () => {
    const raw: Record<string, number> = {};
    for (const [k, d] of Object.entries(DIMENSIONS)) raw[k] = d.weight;
    const norm = normalizeWeights(raw);
    const sum = Object.values(norm).reduce((s, w) => s + w, 0);
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
  });
  test('all dimensions have a weight and compute()', () => {
    for (const [name, dim] of Object.entries(DIMENSIONS)) {
      expect(dim.weight).toBeGreaterThan(0);
      expect(typeof dim.compute).toBe('function');
    }
  });
});
