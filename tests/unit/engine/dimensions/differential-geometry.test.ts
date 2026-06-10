import { describe, expect, test } from 'bun:test';
import { DifferentialGeometryDimension } from '../../../../src/engine/dimensions/differential-geometry.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

describe('DifferentialGeometryDimension', () => {
  test('weight is 0.02', () => expect(new DifferentialGeometryDimension().weight).toBe(0.02));
  test('no neighbors = 0', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    expect(new DifferentialGeometryDimension().compute(cpg.getNode('x')!, cpg)).toBe(0);
  });
  test('uniform neighbors = 0', () => {
    const cpg = createCPG(
      new Map([
        ['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['y', { id: 'y', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { complexity: 5 } }],
      ]),
      [{ source: 'x', target: 'y', kind: 'data' }], 'php'
    );
    expect(new DifferentialGeometryDimension().compute(cpg.getNode('x')!, cpg)).toBe(0);
  });
  test('varied neighbors = high risk', () => {
    const cpg = createCPG(
      new Map([
        ['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['y', { id: 'y', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { complexity: 1 } }],
        ['z', { id: 'z', type: 'stmt', file: 'a', line: 3, col: 0, code: '', language: 'php', features: { complexity: 10 } }],
      ]),
      [
        { source: 'x', target: 'y', kind: 'data' },
        { source: 'x', target: 'z', kind: 'data' },
      ], 'php'
    );
    // std dev = 4.5, /10 = 0.45
    const v = new DifferentialGeometryDimension().compute(cpg.getNode('x')!, cpg);
    expect(v).toBeGreaterThan(0.3);
  });
  test('output clamped to [0,1]', () => {
    const cpg = createCPG(
      new Map([
        ['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['y', { id: 'y', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { complexity: 100 } }],
      ]),
      [{ source: 'x', target: 'y', kind: 'data' }], 'php'
    );
    expect(new DifferentialGeometryDimension().compute(cpg.getNode('x')!, cpg)).toBeLessThanOrEqual(1);
  });
});