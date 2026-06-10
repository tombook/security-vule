import { describe, expect, test } from 'bun:test';
import { DIMENSIONS, normalizeWeights } from '../../../../src/engine/dimensions/registry.js';

describe('P1+P2 dimensions integration', () => {
  test('all 8 new dimensions registered', () => {
    for (const name of ['perturbation', 'tidal', 'relativistic', 'darkMatter', 'entropy', 'quantum', 'topology', 'information']) {
      expect(DIMENSIONS[name]).toBeDefined();
    }
  });
  test('total of all weights normalizes to 1.0', () => {
    const raw: Record<string, number> = {};
    for (const [k, d] of Object.entries(DIMENSIONS)) raw[k] = d.weight;
    const norm = normalizeWeights(raw);
    const sum = Object.values(norm).reduce((s, w) => s + w, 0);
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
  });
  test('total dimensions count after Sprint 4 (13) — Sprint 6 brings total to 19', () => {
    expect(Object.keys(DIMENSIONS).length).toBeGreaterThanOrEqual(13);
  });
  test('P1 weights match spec', () => {
    expect(DIMENSIONS.perturbation.weight).toBe(0.05);
    expect(DIMENSIONS.tidal.weight).toBe(0.10);
    expect(DIMENSIONS.relativistic.weight).toBe(0.10);
    expect(DIMENSIONS.darkMatter.weight).toBe(0.08);
    expect(DIMENSIONS.entropy.weight).toBe(0.05);
  });
  test('P2 weights match spec', () => {
    expect(DIMENSIONS.quantum.weight).toBe(0.07);
    expect(DIMENSIONS.topology.weight).toBe(0.05);
    expect(DIMENSIONS.information.weight).toBe(0.04);
  });
});