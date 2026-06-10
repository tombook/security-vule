import { describe, expect, test } from 'bun:test';
import { FractalDimension } from '../../../../src/engine/dimensions/fractal.js';
import type { CPGNode, CPG } from '../../../../src/engine/cpg/types.js';

function n(features: Record<string, number> = {}): CPGNode {
  return { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features };
}

describe('FractalDimension', () => {
  test('weight is 0.02', () => expect(new FractalDimension().weight).toBe(0.02));
  test('optimal D=1.5 = 0', () => {
    expect(new FractalDimension().compute(n({ self_similarity: 1.5 }), {} as CPG)).toBe(0);
  });
  test('extreme D=2.5 = 1', () => {
    expect(new FractalDimension().compute(n({ self_similarity: 2.5 }), {} as CPG)).toBe(1);
  });
  test('low D=0.5 = 1 (no self-similarity)', () => {
    expect(new FractalDimension().compute(n({ self_similarity: 0.5 }), {} as CPG)).toBe(1);
  });
  test('undefined = 1 (max deviation from optimal)', () => {
    expect(new FractalDimension().compute(n(), {} as CPG)).toBe(1);
  });
});