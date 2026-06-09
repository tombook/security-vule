import { describe, it, expect } from 'bun:test';
import { buildProgramGraph, graphToAdjacencyList, getEdgeStats, type ProgramGraph } from '../../../src/engine/program-graph.js';

function makeAST() {
  return {
    id: 'root',
    type: 'Program',
    code: 'const x = 1; function foo() { return x; }',
    lineNumber: 1,
    endLineNumber: 1,
    children: [
      {
        id: 'varDecl',
        type: 'VariableDeclaration',
        code: 'const x = 1;',
        lineNumber: 1,
        endLineNumber: 1,
        children: [],
        properties: new Map(),
      },
      {
        id: 'funcDecl',
        type: 'FunctionDeclaration',
        code: 'function foo() { return x; }',
        lineNumber: 1,
        endLineNumber: 1,
        children: [
          {
            id: 'returnStmt',
            type: 'ReturnStatement',
            code: 'return x;',
            lineNumber: 1,
            endLineNumber: 1,
            children: [],
            properties: new Map(),
          },
        ],
        properties: new Map([['name', 'foo']]),
      },
    ],
    properties: new Map(),
  };
}

describe('Program Graph Builder', () => {
  it('builds AST nodes and edges from AST', () => {
    const graph = buildProgramGraph(makeAST());

    expect(graph.nodeCount).toBe(4);
    expect(graph.edges.some(e => e.type === 'AST')).toBe(true);
    expect(graph.edgeTypeCounts.AST).toBe(3);
  });

  it('assigns unique IDs to all nodes', () => {
    const graph = buildProgramGraph(makeAST());
    const ids = [...graph.nodes.keys()];
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it('preserves node properties from AST', () => {
    const graph = buildProgramGraph(makeAST());

    const funcNode = [...graph.nodes.values()].find(n => n.type === 'FunctionDeclaration');
    expect(funcNode).toBeDefined();
    expect(funcNode!.properties.get('name')).toBe('foo');
  });

  it('adds FALLS_TO edges for sequential lines', () => {
    const ast = {
      id: 'root',
      type: 'Program',
      code: 'a;\nb;\nc;',
      lineNumber: 1,
      endLineNumber: 3,
      children: [
        { id: 'n1', type: 'Expr1', code: 'a;', lineNumber: 1, endLineNumber: 1, children: [], properties: new Map() },
        { id: 'n2', type: 'Expr2', code: 'b;', lineNumber: 2, endLineNumber: 2, children: [], properties: new Map() },
        { id: 'n3', type: 'Expr3', code: 'c;', lineNumber: 3, endLineNumber: 3, children: [], properties: new Map() },
      ],
      properties: new Map(),
    };

    const graph = buildProgramGraph(ast);
    const fallsTo = graph.edges.filter(e => e.type === 'FALLS_TO');
    expect(fallsTo.length).toBeGreaterThanOrEqual(1);
  });

  it('adds DFG edges from code string', () => {
    const ast = {
      id: 'root',
      type: 'Program',
      code: 'let x = 1;\nlet y = x + 2;',
      lineNumber: 1,
      endLineNumber: 2,
      children: [
        { id: 'def', type: 'VarDef', code: 'let x = 1;', lineNumber: 1, endLineNumber: 1, children: [], properties: new Map() },
        { id: 'use', type: 'VarUse', code: 'let y = x + 2;', lineNumber: 2, endLineNumber: 2, children: [], properties: new Map() },
      ],
      properties: new Map(),
    };

    const graph = buildProgramGraph(ast, undefined, 'let x = 1;\nlet y = x + 2;');
    const dfg = graph.edges.filter(e => e.type === 'DFG');
    expect(dfg.length).toBeGreaterThanOrEqual(1);
  });

  it('adds CALL edges for function calls', () => {
    const ast = {
      id: 'root',
      type: 'Program',
      code: 'foo();',
      lineNumber: 1,
      endLineNumber: 1,
      children: [
        { id: 'call', type: 'CallExpr', code: 'foo();', lineNumber: 1, endLineNumber: 1, children: [], properties: new Map() },
        { id: 'func', type: 'FuncDecl', code: 'function foo() {}', lineNumber: 1, endLineNumber: 1, children: [], properties: new Map([['name', 'foo']]) },
      ],
      properties: new Map(),
    };

    const graph = buildProgramGraph(ast);
    const calls = graph.edges.filter(e => e.type === 'CALL');
    expect(calls.length).toBeGreaterThanOrEqual(1);
  });

  it('graphToAdjacencyList builds correct adj structure', () => {
    const graph = buildProgramGraph(makeAST());
    const adj = graphToAdjacencyList(graph);

    expect(adj.size).toBe(graph.nodeCount);
    for (const [, neighbors] of adj) {
      for (const n of neighbors) {
        expect(n.target).toBeDefined();
        expect(n.type).toBeDefined();
      }
    }
  });

  it('getEdgeStats returns readable string', () => {
    const graph = buildProgramGraph(makeAST());
    const stats = getEdgeStats(graph);

    expect(stats).toContain('AST:');
    expect(stats.length).toBeGreaterThan(0);
  });

  it('handles empty AST gracefully', () => {
    const ast = {
      id: 'empty',
      type: 'Program',
      code: '',
      lineNumber: 1,
      endLineNumber: 1,
      children: [],
      properties: new Map(),
    };

    const graph = buildProgramGraph(ast);
    expect(graph.nodeCount).toBe(1);
    expect(graph.edges.length).toBe(0);
  });
});
