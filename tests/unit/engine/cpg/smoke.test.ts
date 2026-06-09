import { describe, expect, test } from 'bun:test';
import {
  CPGBuilder,
  bfs, allPaths, downstreamNodes,
  computeDegreeStats,
  isSinkFunction,
} from '../../../../src/engine/cpg/index.js';
import type { ProgramGraph } from '../../../../src/engine/program-graph.js';

describe('CPG end-to-end smoke', () => {
  test('build a real CPG from ProgramGraph and query it', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['n1', { id: 'n1', type: 'variable', code: '$_GET["x"]', lineStart: 1, lineEnd: 1, properties: new Map() }],
        ['n2', { id: 'n2', type: 'call', code: 'mysql_query($q)', lineStart: 2, lineEnd: 2, properties: new Map() }],
        ['n3', { id: 'n3', type: 'variable', code: '$q', lineStart: 2, lineEnd: 2, properties: new Map() }],
      ]),
      edges: [
        { source: 'n1', target: 'n3', type: 'DFG' },
        { source: 'n3', target: 'n2', type: 'DFG' },
      ],
      nodeCount: 3,
      edgeCount: 2,
      edgeTypeCounts: {} as any,
      filePath: 'sqli.php',
      language: 'php',
    } as any;

    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg);

    expect(cpg.nodes.size).toBe(3);
    expect(cpg.edges.filter(e => e.kind === 'data')).toHaveLength(2);

    const sinks = cpg.sinkNodes();
    expect(sinks).toHaveLength(1);
    expect(sinks[0].code).toContain('mysql_query');

    const sources = cpg.sourcesFor('n2');
    expect(sources.some(s => s.code.includes('$_GET'))).toBe(true);

    const path = cpg.shortestPath('n1', 'n2');
    expect(path).toEqual(['n1', 'n3', 'n2']);

    const stats = computeDegreeStats(cpg);
    expect(stats.nodeCount).toBe(3);
  });

  test('isSinkFunction recognizes common sinks', () => {
    expect(isSinkFunction('mysql_query', 'php')).toBe(true);
    expect(isSinkFunction('shell_exec', 'php')).toBe(true);
    expect(isSinkFunction('safe_func', 'php')).toBe(false);
  });

  test('downstreamNodes finds reachable sinks', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['src', { id: 'src', type: 'variable', code: '$x', lineStart: 1, lineEnd: 1, properties: new Map() }],
        ['sink', { id: 'sink', type: 'call', code: 'mysql_query($x)', lineStart: 2, lineEnd: 2, properties: new Map() }],
      ]),
      edges: [{ source: 'src', target: 'sink', type: 'DFG' }],
      nodeCount: 2, edgeCount: 1, edgeTypeCounts: {} as any,
      filePath: 'a.php', language: 'php',
    } as any;
    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg) as any;
    const ds = downstreamNodes(cpg, 'src');
    expect(ds).toContain('sink');
  });

  test('allPaths finds multiple paths', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['a', { id: 'a', type: 'var', code: '', lineStart: 1, lineEnd: 1, properties: new Map() }],
        ['b', { id: 'b', type: 'stmt', code: '', lineStart: 2, lineEnd: 2, properties: new Map() }],
        ['c', { id: 'c', type: 'stmt', code: '', lineStart: 3, lineEnd: 3, properties: new Map() }],
        ['d', { id: 'd', type: 'stmt', code: 'sink()', lineStart: 4, lineEnd: 4, properties: new Map() }],
      ]),
      edges: [
        { source: 'a', target: 'b', type: 'DFG' },
        { source: 'a', target: 'c', type: 'DFG' },
        { source: 'b', target: 'd', type: 'DFG' },
        { source: 'c', target: 'd', type: 'DFG' },
      ],
      nodeCount: 4, edgeCount: 4, edgeTypeCounts: {} as any,
      filePath: 'a.php', language: 'php',
    } as any;
    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg) as any;
    const paths = allPaths(cpg, 'a', 'd');
    expect(paths.length).toBe(2);
  });

  test('bfs returns all reachable nodes', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['a', { id: 'a', type: 'var', code: '', lineStart: 1, lineEnd: 1, properties: new Map() }],
        ['b', { id: 'b', type: 'stmt', code: '', lineStart: 2, lineEnd: 2, properties: new Map() }],
      ]),
      edges: [{ source: 'a', target: 'b', type: 'DFG' }],
      nodeCount: 2, edgeCount: 1, edgeTypeCounts: {} as any,
      filePath: 'a.php', language: 'php',
    } as any;
    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg) as any;
    expect(bfs(cpg, 'a')).toEqual(['a', 'b']);
  });
});