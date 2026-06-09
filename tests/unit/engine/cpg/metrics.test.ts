import { describe, expect, test } from 'bun:test';
import { computePagerank, computeBetweenness, computeDegreeStats } from '../../../../src/engine/cpg/metrics.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

function fixture(): CPG {
  return {
    nodes: new Map([
      ['n1', { id: 'n1', type: 'var', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }],
      ['n2', { id: 'n2', type: 'stmt', file: 'a.php', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ['n3', { id: 'n3', type: 'stmt', file: 'a.php', line: 3, col: 0, code: '', language: 'php', features: {} }],
    ]),
    edges: [
      { source: 'n1', target: 'n2', kind: 'data' },
      { source: 'n2', target: 'n3', kind: 'data' },
      { source: 'n1', target: 'n3', kind: 'data' },
    ],
    language: 'php',
    getNode: () => undefined as any,
    outEdges: (id: string) => {
      const all: any[] = [
        { source: 'n1', target: 'n2', kind: 'data' },
        { source: 'n2', target: 'n3', kind: 'data' },
        { source: 'n1', target: 'n3', kind: 'data' },
      ];
      return all.filter(e => e.source === id);
    },
    inEdges: (id: string) => {
      const all: any[] = [
        { source: 'n1', target: 'n2', kind: 'data' },
        { source: 'n2', target: 'n3', kind: 'data' },
        { source: 'n1', target: 'n3', kind: 'data' },
      ];
      return all.filter(e => e.target === id);
    },
    shortestPath: () => null,
    sinkNodes: () => [],
    sourcesFor: () => [],
    functions: () => [],
    callGraph: () => [],
    inDegree: (id: string) => {
      const map: any = { n1: 0, n2: 1, n3: 2 };
      return map[id] || 0;
    },
    outDegree: (id: string) => {
      const map: any = { n1: 2, n2: 1, n3: 0 };
      return map[id] || 0;
    },
  } as any;
}

describe('CPG metrics', () => {
  test('pagerank sums to ~1.0', () => {
    const cpg = fixture() as any;
    const pr = computePagerank(cpg, 50);
    const sum = Array.from(pr.values()).reduce((s, v) => s + v, 0);
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
  });

  test('pagerank assigns highest score to sink node (most incoming)', () => {
    const cpg = fixture() as any;
    const pr = computePagerank(cpg, 50);
    // n3 is a sink (receives from n1 and n2) — gets highest PageRank
    expect(pr.get('n3')!).toBeGreaterThan(pr.get('n1')!);
  });

  test('betweenness returns map with 3 nodes', () => {
    const cpg = fixture() as any;
    const bc = computeBetweenness(cpg);
    expect(bc.size).toBe(3);
  });

  test('degreeStats returns aggregate counts', () => {
    const cpg = fixture() as any;
    const stats = computeDegreeStats(cpg);
    expect(stats.nodeCount).toBe(3);
    expect(stats.edgeCount).toBe(3);
    expect(stats.avgDegree).toBeCloseTo(2, 1);
  });
});