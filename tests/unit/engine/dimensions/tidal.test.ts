import { describe, expect, test } from 'bun:test';
import { TidalDimension } from '../../../../src/engine/dimensions/tidal.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

describe('TidalDimension', () => {
  test('weight is 0.10', () => expect(new TidalDimension().weight).toBe(0.10));
  test('single sink = 0 risk', () => {
    const cpg = createCPG(
      new Map([['s', { id: 's', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { is_sink: 1 } }]]),
      [], 'php'
    );
    expect(new TidalDimension().compute(cpg.getNode('s')!, cpg)).toBe(0);
  });
  test('two close sinks = high risk', () => {
    const cpg = createCPG(
      new Map([
        ['s1', { id: 's1', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
        ['s2', { id: 's2', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
      ]),
      [{ source: 's1', target: 's2', kind: 'data' }], 'php'
    );
    expect(new TidalDimension().compute(cpg.getNode('s1')!, cpg)).toBeGreaterThan(0);
  });
  test('distant sinks = low risk', () => {
    const cpg = createCPG(
      new Map([
        ['s1', { id: 's1', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
        ['s2', { id: 's2', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
        ['m1', { id: 'm1', type: 'stmt', file: 'a', line: 3, col: 0, code: '', language: 'php', features: {} }],
        ['m2', { id: 'm2', type: 'stmt', file: 'a', line: 4, col: 0, code: '', language: 'php', features: {} }],
        ['m3', { id: 'm3', type: 'stmt', file: 'a', line: 5, col: 0, code: '', language: 'php', features: {} }],
        ['m4', { id: 'm4', type: 'stmt', file: 'a', line: 6, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 's1', target: 'm1', kind: 'data' },
        { source: 'm1', target: 'm2', kind: 'data' },
        { source: 'm2', target: 'm3', kind: 'data' },
        { source: 'm3', target: 'm4', kind: 'data' },
        { source: 'm4', target: 's2', kind: 'data' },
      ], 'php'
    );
    expect(new TidalDimension().compute(cpg.getNode('s1')!, cpg)).toBe(0);
  });
  test('output clamped to [0,1]', () => {
    const cpg = createCPG(
      new Map([
        ['s1', { id: 's1', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
        ['s2', { id: 's2', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
      ]),
      [{ source: 's1', target: 's2', kind: 'data' }], 'php'
    );
    const v = new TidalDimension().compute(cpg.getNode('s1')!, cpg);
    expect(v).toBeLessThanOrEqual(1);
  });
});