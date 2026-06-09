import { describe, expect, test } from 'bun:test';
import { DIMENSIONS, registerDimension, getEnabledDimensions, normalizeWeights } from '../../../../src/engine/dimensions/registry.js';
import { BaseDimension } from '../../../../src/engine/dimensions/base.js';
import type { CPG, CPGNode } from '../../../../src/engine/cpg/types.js';

class CustomDim extends BaseDimension {
  readonly name = 'custom';
  readonly weight = 0.3;
  compute(_node: CPGNode, _cpg: CPG): number { return 0.5; }
}

describe('Dimension Registry', () => {
  test('ast placeholder is registered by default', () => {
    expect(DIMENSIONS['ast']).toBeDefined();
    expect(DIMENSIONS['ast'].weight).toBe(0.15);
  });

  test('registerDimension adds a new dimension', () => {
    const before = Object.keys(DIMENSIONS).length;
    registerDimension(new CustomDim());
    expect(DIMENSIONS['custom']).toBeDefined();
    expect(Object.keys(DIMENSIONS).length).toBe(before + 1);
    delete DIMENSIONS['custom']; // cleanup
  });

  test('getEnabledDimensions returns all when flags empty', () => {
    const dims = getEnabledDimensions({});
    expect(dims.length).toBe(Object.keys(DIMENSIONS).length);
  });

  test('getEnabledDimensions filters out disabled', () => {
    registerDimension(new CustomDim());
    const dims = getEnabledDimensions({ ast: true, custom: false });
    expect(dims.find(d => d.name === 'ast')).toBeDefined();
    expect(dims.find(d => d.name === 'custom')).toBeUndefined();
    delete DIMENSIONS['custom'];
  });

  test('normalizeWeights rescales positive weights to sum=1', () => {
    const w = normalizeWeights({ a: 0.5, b: 0.3, c: 0 });
    expect(w.a + w.b).toBeCloseTo(1.0);
    expect(w.c).toBe(0);
  });

  test('normalizeWeights handles all-zero (returns input)', () => {
    const w = normalizeWeights({ a: 0, b: 0 });
    expect(w.a).toBe(0);
    expect(w.b).toBe(0);
  });
});