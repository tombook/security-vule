import { describe, expect, test } from 'bun:test';
import { OrbitalDimension } from '../../../../src/engine/dimensions/orbital.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

function hubCPG(): CPG {
  return createCPG(
    new Map([
      ['hub', { id: 'hub', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: { pagerank: 0.8, betweenness: 0.9 } }],
      ['leaf', { id: 'leaf', type: 'stmt', file: 'a.php', line: 2, col: 0, code: '', language: 'php', features: { pagerank: 0.05, betweenness: 0.0 } }],
      ['s', { id: 's', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'sink', language: 'php', features: { is_sink: 1 } }],
    ]),
    [
      { source: 'leaf', target: 'hub', kind: 'data' },
      { source: 'hub', target: 's', kind: 'data' },
    ], 'php'
  );
}

describe('OrbitalDimension', () => {
  test('weight is 0.10', () => {
    expect(new OrbitalDimension().weight).toBe(0.10);
  });
  test('centrality-loaded node returns higher risk', () => {
    const cpg = hubCPG();
    const dim = new OrbitalDimension();
    const hub = dim.compute(cpg.getNode('hub')!, cpg);
    const leaf = dim.compute(cpg.getNode('leaf')!, cpg);
    expect(hub).toBeGreaterThan(leaf);
  });
  test('empty features returns 0', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    expect(new OrbitalDimension().compute(cpg.getNode('x')!, cpg)).toBe(0);
  });
  test('output clamped to [0,1]', () => {
    const cpg = hubCPG();
    const dim = new OrbitalDimension();
    for (const n of cpg.nodes.values()) {
      const v = dim.compute(n, cpg);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });
});