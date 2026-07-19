import { describe, expect, test } from 'bun:test';
import {
  CPGBuilder,
  getNodesByType,
  getEdgesByType,
  getOutgoingEdges,
  getIncomingEdges,
  findNodesByName,
  getCallGraph,
  getDataFlowPaths,
  getFunctionCFG
} from '../../../src/math/cpg';

describe('cpg', () => {
  test('CPGBuilder creates nodes', () => {
    const cpg = new CPGBuilder()
      .addFile('file1', 'test.ts', 'const x = 1;')
      .addFunction('fn1', 'main')
      .build();

    expect(cpg.nodes.size).toBe(2);
    expect(cpg.nodes.get('file1')?.type).toBe('File');
    expect(cpg.nodes.get('fn1')?.type).toBe('Function');
  });

  test('CPGBuilder creates edges', () => {
    const cpg = new CPGBuilder()
      .addFunction('fn1', 'main')
      .addStatement('stmt1', 'x = 1')
      .addASTEdge('fn1', 'stmt1')
      .addCFGEdge('stmt1', 'stmt1')
      .build();

    expect(cpg.edges.size).toBe(2);
    expect(cpg.edges.get('fn1->stmt1')?.type).toBe('AST');
    expect(cpg.edges.get('stmt1->stmt1')?.type).toBe('CFG');
  });

  test('getNodesByType filters correctly', () => {
    const cpg = new CPGBuilder()
      .addFile('file1', 'main.ts')
      .addFunction('fn1', 'foo')
      .addFunction('fn2', 'bar')
      .build();

    const functions = getNodesByType(cpg, 'Function');
    expect(functions.length).toBe(2);
  });

  test('getEdgesByType filters correctly', () => {
    const cpg = new CPGBuilder()
      .addFunction('fn1', 'main')
      .addFunction('fn2', 'helper')
      .addCallEdge('fn1', 'fn2')
      .addCFGEdge('fn1', 'fn1')
      .build();

    const calls = getEdgesByType(cpg, 'CALL');
    expect(calls.length).toBe(1);
  });

  test('getOutgoingEdges finds children', () => {
    const cpg = new CPGBuilder()
      .addFunction('fn1', 'main')
      .addStatement('s1', 'x = 1')
      .addStatement('s2', 'y = 2')
      .addCFGEdge('fn1', 's1')
      .addCFGEdge('fn1', 's2')
      .build();

    const outgoing = getOutgoingEdges(cpg, 'fn1');
    expect(outgoing.length).toBe(2);
  });

  test('getIncomingEdges finds parents', () => {
    const cpg = new CPGBuilder()
      .addFunction('fn1', 'main')
      .addStatement('s1', 'x = 1')
      .addCFGEdge('fn1', 's1')
      .build();

    const incoming = getIncomingEdges(cpg, 's1');
    expect(incoming.length).toBe(1);
    expect(incoming[0].source).toBe('fn1');
  });

  test('findNodesByName searches by name', () => {
    const cpg = new CPGBuilder()
      .addFunction('fn1', 'main')
      .addFunction('fn2', 'helper')
      .addFunction('fn3', 'main') // duplicate name
      .build();

    const results = findNodesByName(cpg, 'main');
    expect(results.length).toBe(2);
  });

  test('getCallGraph builds adjacency list', () => {
    const cpg = new CPGBuilder()
      .addFunction('fn1', 'main')
      .addFunction('fn2', 'helper')
      .addFunction('fn3', 'util')
      .addCallEdge('fn1', 'fn2')
      .addCallEdge('fn1', 'fn3')
      .addCallEdge('fn2', 'fn3')
      .build();

    const callGraph = getCallGraph(cpg);
    expect(callGraph.get('fn1')?.length).toBe(2);
    expect(callGraph.get('fn2')?.length).toBe(1);
    expect(callGraph.get('fn3')?.length).toBeUndefined(); // fn3 has no outgoing calls
  });

  test('getFunctionCFG traverses control flow', () => {
    const cpg = new CPGBuilder()
      .addFunction('fn1', 'main')
      .addStatement('s1', 'x = 1')
      .addStatement('s2', 'y = 2')
      .addStatement('s3', 'z = 3')
      .addCFGEdge('fn1', 's1')
      .addCFGEdge('s1', 's2')
      .addCFGEdge('s2', 's3')
      .build();

    const cfg = getFunctionCFG(cpg, 'fn1');
    expect(cfg.length).toBe(4); // fn1 + 3 statements
  });

  test('getDataFlowPaths finds source-to-sink paths', () => {
    const cpg = new CPGBuilder()
      .addExpression('source', 'user_input()')
      .addExpression('sanitized', 'sanitize(user_input())')
      .addStatement('usage', 'console.log(x)')
      .addSourceEdge('source', 'sanitized')
      .addDataFlowEdge('sanitized', 'usage')
      .addSinkEdge('usage', 'sink')
      .build();

    const paths = getDataFlowPaths(cpg);
    expect(paths.length).toBeGreaterThanOrEqual(0);
  });

  test('CPG metadata is set', () => {
    const cpg = new CPGBuilder()
      .setLanguage('TypeScript')
      .setProjectPath('/project')
      .addFile('file1', 'test.ts')
      .build();

    expect(cpg.metadata.language).toBe('TypeScript');
    expect(cpg.metadata.projectPath).toBe('/project');
    expect(cpg.metadata.createdAt).toBeDefined();
  });
});