import { describe, expect, test } from 'bun:test';
import { KeplerDimension } from '../../../../src/engine/dimensions/kepler.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

function chainCPG(): CPG {
  return createCPG(
    new Map([
      ['n1', { id: 'n1', type: 'var', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }],
      ['n2', { id: 'n2', type: 'stmt', file: 'a.php', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ['n3', { id: 'n3', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'sink()', language: 'php', features: { is_sink: 1 } }],
    ]),
    [
      { source: 'n1', target: 'n2', kind: 'data' },
      { source: 'n2', target: 'n3', kind: 'data' },
    ],
    'php',
  );
}

describe('KeplerDimension', () => {
  test('weight is 0.15', () => {
    expect(new KeplerDimension().weight).toBe(0.15);
  });
  test('node closer to sink has higher score', () => {
    const cpg = chainCPG();
    const dim = new KeplerDimension();
    const n2 = dim.compute(cpg.getNode('n2')!, cpg);
    const n1 = dim.compute(cpg.getNode('n1')!, cpg);
    expect(n2).toBeGreaterThan(n1);
  });
  test('isolated node returns 0', () => {
    const cpg = createCPG(
      new Map([['iso', { id: 'iso', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    const dim = new KeplerDimension();
    expect(dim.compute(cpg.getNode('iso')!, cpg)).toBe(0);
  });
  test('hyperbolic eccentricity (>1) boosts risk', () => {
    const cpg = createCPG(
      new Map([
        ['src', { id: 'src', type: 'var', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['s1', { id: 's1', type: 'stmt', file: 'a.php', line: 2, col: 0, code: 'sink1', language: 'php', features: { is_sink: 1 } }],
        ['s2', { id: 's2', type: 'stmt', file: 'a.php', line: 6, col: 0, code: 'sink2', language: 'php', features: { is_sink: 1 } }],
        ['s3', { id: 's3', type: 'stmt', file: 'a.php', line: 11, col: 0, code: 'sink3', language: 'php', features: { is_sink: 1 } }],
      ]),
      [
        { source: 'src', target: 's1', kind: 'data' },
        { source: 'src', target: 's2', kind: 'data' },
        { source: 'src', target: 's3', kind: 'data' },
      ], 'php'
    );
    const dim = new KeplerDimension();
    const v = dim.compute(cpg.getNode('src')!, cpg);
    expect(v).toBeGreaterThan(0.1);
  });
  test('output clamped to [0,1]', () => {
    const cpg = chainCPG();
    const dim = new KeplerDimension();
    for (const n of cpg.nodes.values()) {
      const v = dim.compute(n, cpg);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });
});