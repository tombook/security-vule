import { describe, expect, test } from 'bun:test';
import { TdaDimension } from '../../../../src/engine/dimensions/tda.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

describe('TdaDimension', () => {
  test('weight is 0.03', () => expect(new TdaDimension().weight).toBe(0.03));
  test('single node = 0', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }]]),
      [], 'typescript'
    );
    expect(new TdaDimension().compute(cpg.getNode('x')!, cpg)).toBe(0);
  });
  test('linear chain = 0 (no cycles)', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'typescript', features: {} }],
      ]),
      [{ source: 'a', target: 'b', kind: 'data' }], 'typescript'
    );
    expect(new TdaDimension().compute(cpg.getNode('a')!, cpg)).toBe(0);
  });
  test('cycle = positive beta1', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'typescript', features: {} }],
      ]),
      [
        { source: 'a', target: 'b', kind: 'data' },
        { source: 'b', target: 'a', kind: 'data' },
      ], 'typescript'
    );
    // 2 nodes, 2 edges, beta0=1 → beta1 = 2 - 2 + 1 = 1
    const v = new TdaDimension().compute(cpg.getNode('a')!, cpg);
    expect(v).toBeGreaterThan(0);
  });
  test('output clamped to [0,1]', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'typescript', features: {} }],
      ]),
      [{ source: 'a', target: 'b', kind: 'data' }], 'typescript'
    );
    const v = new TdaDimension().compute(cpg.getNode('a')!, cpg);
    expect(v).toBeLessThanOrEqual(1);
  });
});