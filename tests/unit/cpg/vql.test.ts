/**
 * Tests for VQL — Vule Query Language (declarative CPG query DSL).
 */
import { describe, expect, test } from 'bun:test';
import {
  createCPG,
  query,
  predicates,
  type CPGNode,
  type CPG,
} from '../../../src/engine/cpg/index.js';

function buildTestCpg(): CPG {
  const nodes = new Map<string, CPGNode>();
  const nodes_data = [
    { id: 'n1', type: 'expr' as const, code: "$_GET['id']", line: 2 },
    { id: 'n2', type: 'expr' as const, code: '$id = $_GET["id"]', line: 2 },
    {
      id: 'n3',
      type: 'expr' as const,
      code: 'mysql_query("SELECT * FROM users WHERE id=" . $id)',
      line: 3,
    },
    { id: 'n4', type: 'expr' as const, code: 'echo $user', line: 4 },
    { id: 'n5', type: 'expr' as const, code: 'system("ls " . $id)', line: 5 },
    { id: 'n6', type: 'stmt' as const, code: 'echo "hello"', line: 7 },
  ];
  for (const n of nodes_data) {
    nodes.set(n.id, {
      id: n.id,
      type: n.type,
      file: 'test.php',
      line: n.line,
      col: 0,
      code: n.code,
      language: 'php',
      features: {},
    });
  }
  const edges = [
    { source: 'n2', target: 'n3', kind: 'data' as const },
    { source: 'n3', target: 'n4', kind: 'data' as const },
    { source: 'n2', target: 'n5', kind: 'data' as const },
    { source: 'n6', target: 'n1', kind: 'ast_child' as const },
  ];
  return createCPG(nodes, edges, 'php');
}

describe('VQL — built-in predicates', () => {
  test('nodeType filters by type', () => {
    const cpg = buildTestCpg();
    const result = query(cpg).where('stmts', predicates.nodeType('stmt')).execute();
    expect(result.nodes.length).toBeGreaterThan(0);
    for (const n of result.nodes) expect(n.type).toBe('stmt');
  });

  test('codeContains finds substring', () => {
    const cpg = buildTestCpg();
    const result = query(cpg).where('mysql', predicates.codeContains('mysql')).execute();
    expect(result.nodes.length).toBeGreaterThan(0);
    for (const n of result.nodes) expect(n.code.includes('mysql')).toBe(true);
  });

  test('codeMatches regex', () => {
    const cpg = buildTestCpg();
    const result = query(cpg)
      .where('system', predicates.codeMatches(/\bsystem\s*\(/))
      .execute();
    expect(result.nodes.length).toBe(1);
    expect(result.nodes[0]?.code).toContain('system');
  });

  test('inFile filters by file', () => {
    const cpg = buildTestCpg();
    const result = query(cpg).where('this', predicates.inFile('test.php')).execute();
    expect(result.nodes.length).toBe(6);
  });

  test('isUserInput (php) finds $_GET', () => {
    const cpg = buildTestCpg();
    const result = query(cpg).where('userInput', predicates.isUserInput('php')).execute();
    expect(result.nodes.length).toBeGreaterThan(0);
    for (const n of result.nodes) expect(n.code).toMatch(/\$_GET/);
  });

  test('isSink (php) finds system/mysql_query', () => {
    const cpg = buildTestCpg();
    const result = query(cpg).where('sinks', predicates.isSink('php')).execute();
    expect(result.nodes.length).toBeGreaterThanOrEqual(2);
  });

  test('atLine finds exact line', () => {
    const cpg = buildTestCpg();
    const result = query(cpg).where('line3', predicates.atLine(3)).execute();
    expect(result.nodes.length).toBe(1);
    expect(result.nodes[0]?.line).toBe(3);
  });

  test('inRange filters by line range', () => {
    const cpg = buildTestCpg();
    const result = query(cpg).where('lines2-4', predicates.inRange(2, 4)).execute();
    expect(result.nodes.every((n) => n.line >= 2 && n.line <= 4)).toBe(true);
  });
});

describe('VQL — predicate combinators', () => {
  test('and() combines predicates', () => {
    const cpg = buildTestCpg();
    const result = query(cpg)
      .where('expr', predicates.nodeType('expr'))
      .and(predicates.codeContains('$'))
      .execute();
    expect(result.nodes.every((n) => n.type === 'expr' && n.code.includes('$'))).toBe(true);
  });

  test('or() unions predicates', () => {
    const cpg = buildTestCpg();
    const result = query(cpg)
      .where('eval', predicates.codeContains('mysql'))
      .or(predicates.codeContains('system'))
      .execute();
    expect(result.nodes.length).toBeGreaterThanOrEqual(2);
  });

  test('not() excludes matches', () => {
    const cpg = buildTestCpg();
    const withMysql = query(cpg).where('a', predicates.codeContains('mysql')).execute();
    const withoutMysql = query(cpg)
      .where('a', predicates.codeContains('mysql'))
      .not(predicates.codeContains('mysql'))
      .execute();
    expect(withoutMysql.nodes.length).toBe(0);
    expect(withMysql.nodes.length).toBeGreaterThan(0);
  });
});

describe('VQL — taint flow queries', () => {
  test('source() + sink() + paths() finds taint paths', () => {
    const cpg = buildTestCpg();
    const result = query(cpg)
      .source(predicates.isUserInput('php'))
      .sink(predicates.isSink('php'))
      .paths({ via: ['data'], maxPaths: 10 })
      .execute();
    expect(result.paths.length).toBeGreaterThan(0);
    for (const p of result.paths) {
      expect(p.source).toBeTruthy();
      expect(p.sink).toBeTruthy();
      expect(p.nodes.length).toBeGreaterThanOrEqual(2);
      expect(p.via).toContain('data');
    }
  });

  test('sourcesOf() finds upstream taint sources', () => {
    const cpg = buildTestCpg();
    const sink = cpg.nodes.get('n5');
    if (sink) {
      const result = query(cpg)
        .sourcesOf(sink.id, { via: ['data'] })
        .execute();
      expect(result.paths.length).toBeGreaterThan(0);
    }
  });

  test('sinksOf() finds downstream sinks', () => {
    const cpg = buildTestCpg();
    const result = query(cpg)
      .sinksOf('n2', { via: ['data'] })
      .execute();
    expect(result.paths.length).toBeGreaterThan(0);
  });
});

describe('VQL — reachability', () => {
  test('reachableFrom() finds downstream nodes', () => {
    const cpg = buildTestCpg();
    const result = query(cpg)
      .reachableFrom('n2', { via: ['data'] })
      .execute();
    expect(result.paths.length).toBeGreaterThan(0);
  });
});

describe('VQL — performance', () => {
  test('returns elapsedMs in result', () => {
    const cpg = buildTestCpg();
    const result = query(cpg)
      .where('all', () => true)
      .execute();
    expect(typeof result.elapsedMs).toBe('number');
    expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  test('predicateCount reflects complexity', () => {
    const cpg = buildTestCpg();
    const simple = query(cpg)
      .where('a', () => true)
      .execute();
    const complex = query(cpg)
      .where('a', () => true)
      .where('b', () => true)
      .where('c', () => true)
      .where('d', () => true)
      .execute();
    expect(complex.predicateCount).toBeGreaterThan(simple.predicateCount);
  });
});
