import { describe, expect, test } from 'bun:test';
import { CPGBuilder } from '../../../../src/engine/cpg/builder.js';
import type { ProgramGraph } from '../../../../src/engine/program-graph.js';

function makeStubPG(): ProgramGraph {
  return {
    nodes: new Map([
      ['n1', { id: 'n1', type: 'variable', code: '$_GET["x"]', lineStart: 1, lineEnd: 1, properties: new Map() }],
      ['n2', { id: 'n2', type: 'call', code: 'mysql_query($q)', lineStart: 2, lineEnd: 2, properties: new Map() }],
    ]),
    edges: [{ source: 'n1', target: 'n2', type: 'DFG' }],
    nodeCount: 2,
    edgeCount: 1,
    edgeTypeCounts: {} as any,
    filePath: 'a.php',
    language: 'php',
  } as any;
}

describe('CPGBuilder', () => {
  test('builds CPG from ProgramGraph with 2 nodes', () => {
    const pg = makeStubPG();
    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg);
    expect(cpg.nodes.size).toBe(2);
    expect(cpg.language).toBe('php');
  });

  test('classifies variable node as var', () => {
    const pg = makeStubPG();
    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg);
    const n1 = cpg.nodes.get('n1')!;
    expect(n1.type).toBe('var');
    expect(n1.code).toBe('$_GET["x"]');
  });

  test('classifies mysql_query as sink', () => {
    const pg = makeStubPG();
    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg);
    expect(cpg.sinkNodes().length).toBe(1);
    expect(cpg.sinkNodes()[0].code).toContain('mysql_query');
  });

  test('DFG edge maps to data edge', () => {
    const pg = makeStubPG();
    const cpg = new CPGBuilder('php', pg.filePath || 'a.php').build(pg);
    expect(cpg.edges).toHaveLength(1);
    expect(cpg.edges[0].kind).toBe('data');
  });
});