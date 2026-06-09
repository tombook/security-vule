import { describe, expect, test } from 'bun:test';
import { GravityDimension } from '../../../../src/engine/dimensions/gravity.js';
import { createCPG } from '../../../../src/engine/cpg/builder.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

function cpgWithSink(): CPG {
  return createCPG(
    new Map([
      ['src', { id: 'src', type: 'var', file: 'a.php', line: 1, col: 0, code: '$_GET["x"]', language: 'php', features: { sensitivity: 1 } }],
      ['mid', { id: 'mid', type: 'stmt', file: 'a.php', line: 2, col: 0, code: 'process($x)', language: 'php', features: {} }],
      ['sink', { id: 'sink', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'mysql_query($x)', language: 'php', features: { is_sink: 1, dangerousness: 0.9 } }],
    ]),
    [
      { source: 'src', target: 'mid', kind: 'data' },
      { source: 'mid', target: 'sink', kind: 'data' },
    ],
    'php',
  );
}

describe('GravityDimension', () => {
  test('weight is 0.20 (highest cosmic-galaxy priority)', () => {
    expect(new GravityDimension().weight).toBe(0.20);
  });
  test('sink node gets highest gravity risk', () => {
    const cpg = cpgWithSink();
    const dim = new GravityDimension();
    const sinkScore = dim.compute(cpg.getNode('sink')!, cpg);
    const srcScore = dim.compute(cpg.getNode('src')!, cpg);
    expect(sinkScore).toBeGreaterThan(srcScore);
  });
  test('non-sink non-source node returns low risk', () => {
    const cpg = cpgWithSink();
    const dim = new GravityDimension();
    const midScore = dim.compute(cpg.getNode('mid')!, cpg);
    expect(midScore).toBeLessThan(0.5);
  });
  test('output is clamped to [0,1]', () => {
    const cpg = cpgWithSink();
    const dim = new GravityDimension();
    for (const node of cpg.nodes.values()) {
      const v = dim.compute(node, cpg);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });
  test('no sinks = 0 risk', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    expect(new GravityDimension().compute(cpg.getNode('x')!, cpg)).toBe(0);
  });
  test('closer source = higher risk (1/d² decay)', () => {
    const cpg = createCPG(
      new Map([
        ['src', { id: 'src', type: 'var', file: 'a', line: 1, col: 0, code: '$_GET', language: 'php', features: { sensitivity: 1 } }],
        ['mid', { id: 'mid', type: 'stmt', file: 'a', line: 2, col: 0, code: 'mid', language: 'php', features: { sensitivity: 1 } }],
        ['far', { id: 'far', type: 'stmt', file: 'a', line: 3, col: 0, code: 'far', language: 'php', features: {} }],
        ['far2', { id: 'far2', type: 'stmt', file: 'a', line: 4, col: 0, code: 'far2', language: 'php', features: {} }],
        ['sink', { id: 'sink', type: 'stmt', file: 'a', line: 5, col: 0, code: 'mysql_query()', language: 'php', features: { is_sink: 1, dangerousness: 1 } }],
      ]),
      [
        { source: 'src', target: 'mid', kind: 'data' },
        { source: 'mid', target: 'far', kind: 'data' },
        { source: 'far', target: 'far2', kind: 'data' },
        { source: 'far2', target: 'sink', kind: 'data' },
      ], 'php'
    );
    const dim = new GravityDimension();
    // src path length 5 (d²=25), mid path length 4 (d²=16) → mid closer to sink = higher risk
    const midRisk = dim.compute(cpg.getNode('mid')!, cpg);
    const srcRisk = dim.compute(cpg.getNode('src')!, cpg);
    expect(midRisk).toBeGreaterThan(srcRisk);
  });
});