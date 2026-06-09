import { describe, expect, test } from 'bun:test';
import { TopologyDimension } from '../../../../src/engine/dimensions/topology.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

describe('TopologyDimension', () => {
  test('weight is 0.05', () => expect(new TopologyDimension().weight).toBe(0.05));
  test('acyclic graph = 0', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [{ source: 'a', target: 'b', kind: 'data' }], 'php'
    );
    expect(new TopologyDimension().compute(cpg.getNode('a')!, cpg)).toBe(0);
  });
  test('cyclic graph (a→b→a) = high risk', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 'a', target: 'b', kind: 'data' },
        { source: 'b', target: 'a', kind: 'data' },
      ], 'php'
    );
    expect(new TopologyDimension().compute(cpg.getNode('a')!, cpg)).toBeGreaterThan(0);
  });
  test('output clamped to [0,1]', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 'a', target: 'b', kind: 'data' },
        { source: 'b', target: 'a', kind: 'data' },
      ], 'php'
    );
    const v = new TopologyDimension().compute(cpg.getNode('a')!, cpg);
    expect(v).toBeLessThanOrEqual(1);
  });
});