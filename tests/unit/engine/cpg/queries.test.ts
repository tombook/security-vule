import { describe, expect, test } from 'bun:test';
import { bfs, dfs, allPaths, downstreamNodes, upstreamNodes } from '../../../../src/engine/cpg/queries.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

function fixture(): CPG {
  const edges: any[] = [
    { source: 'n1', target: 'n2', kind: 'data' },
    { source: 'n2', target: 'n3', kind: 'data' },
    { source: 'n1', target: 'n3', kind: 'data' },
  ];
  return {
    nodes: new Map([
      ['n1', { id: 'n1', type: 'var', file: 'a.php', line: 1, col: 0, code: '$a', language: 'php', features: {} }],
      ['n2', { id: 'n2', type: 'stmt', file: 'a.php', line: 2, col: 0, code: 'process($a)', language: 'php', features: {} }],
      ['n3', { id: 'n3', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'sink($a)', language: 'php', features: { is_sink: 1 } }],
    ]),
    edges,
    language: 'php',
    getNode: () => undefined as any,
    outEdges: (id: string) => edges.filter(e => e.source === id),
    inEdges: (id: string) => edges.filter(e => e.target === id),
    shortestPath: () => null,
    sinkNodes: () => [],
    sourcesFor: () => [],
    functions: () => [],
    callGraph: () => [],
    inDegree: () => 0,
    outDegree: () => 0,
  } as any;
}

describe('CPG queries', () => {
  test('bfs from n1 visits n1, n2, n3', () => {
    const cpg = fixture() as any;
    const visited = bfs(cpg, 'n1');
    expect(visited.sort()).toEqual(['n1', 'n2', 'n3']);
  });

  test('downstreamNodes(n1) returns n2, n3', () => {
    const cpg = fixture() as any;
    const ds = downstreamNodes(cpg, 'n1');
    expect(ds.sort()).toEqual(['n2', 'n3']);
  });

  test('upstreamNodes(n3) returns n1, n2', () => {
    const cpg = fixture() as any;
    const us = upstreamNodes(cpg, 'n3');
    expect(us.sort()).toEqual(['n1', 'n2']);
  });

  test('allPaths from n1 to n3 returns both paths', () => {
    const cpg = fixture() as any;
    const paths = allPaths(cpg, 'n1', 'n3');
    expect(paths.length).toBe(2);
  });

  test('dfs from n1 visits all 3 nodes', () => {
    const cpg = fixture() as any;
    const visited = dfs(cpg, 'n1');
    expect(visited.sort()).toEqual(['n1', 'n2', 'n3']);
  });
});