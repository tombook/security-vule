import { describe, expect, test } from 'bun:test';
import {
  cyclomaticComplexity,
  nestingDepth,
  degreeCentrality,
  betweennessCentrality,
  reachability,
  isStronglyConnected,
  pagerank,
  Graph
} from '../../../src/math/graph-metrics';

describe('graph-metrics', () => {
  test('cyclomatic complexity for simple linear graph', () => {
    // Linear: A -> B -> C
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['B', 'C']]
    };
    const result = cyclomaticComplexity(graph);
    expect(result.complexity).toBe(1);
    expect(result.edges).toBe(2);
    expect(result.nodes).toBe(3);
  });

  test('cyclomatic complexity for if statement', () => {
    // Simple decision: A -> B, A -> C (2 edges, 3 nodes, 1 component)
    // M = E - N + 2P = 2 - 3 + 2 = 1
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['A', 'C']]
    };
    const result = cyclomaticComplexity(graph);
    expect(result.complexity).toBe(1);
  });

  test('cyclomatic complexity for loop', () => {
    // Loop: A -> B -> A (cycle)
    const graph: Graph = {
      nodes: ['A', 'B'],
      edges: [['A', 'B'], ['B', 'A']]
    };
    const result = cyclomaticComplexity(graph);
    expect(result.complexity).toBe(2);
  });

  test('nesting depth of AST', () => {
    const ast = {
      type: 'root',
      children: [
        {
          type: 'if',
          children: [
            {
              type: 'block',
              children: [
                { type: 'stmt' }
              ]
            }
          ]
        }
      ]
    };
    const result = nestingDepth(ast);
    expect(result).toBe(3);
  });

  test('degree centrality', () => {
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['A', 'C'], ['B', 'C']]
    };
    const result = degreeCentrality(graph);
    expect(result.get('A')).toBe(2);
    expect(result.get('B')).toBe(2);
    expect(result.get('C')).toBe(2);
  });

  test('pagerank basic', () => {
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['B', 'C'], ['C', 'A']]
    };
    const result = pagerank(graph, 0.85, 10);
    // All nodes should have roughly equal rank in a cycle
    const ranks = Array.from(result.values());
    const avg = ranks.reduce((a, b) => a + b, 0) / ranks.length;
    expect(result.get('A')).toBeCloseTo(avg, 2);
  });

  test('pagerank with hub', () => {
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['A', 'C'], ['B', 'C'], ['C', 'A']]
    };
    const result = pagerank(graph, 0.85, 50);
    // A should have higher rank as it links to everything
    expect(result.get('A')).toBeGreaterThan(0.3);
  });

  test('reachability in directed graph', () => {
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['B', 'C']]
    };
    const result = reachability(graph);
    expect(result.get('A')?.has('B')).toBe(true);
    expect(result.get('A')?.has('C')).toBe(true);
    expect(result.get('B')?.has('C')).toBe(true);
    expect(result.get('B')?.has('A')).toBe(false);
  });

  test('isStronglyConnected for cycle', () => {
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['B', 'C'], ['C', 'A']]
    };
    expect(isStronglyConnected(graph)).toBe(true);
  });

  test('isStronglyConnected returns false for non-cycle', () => {
    const graph: Graph = {
      nodes: ['A', 'B', 'C'],
      edges: [['A', 'B'], ['B', 'C']]
    };
    expect(isStronglyConnected(graph)).toBe(false);
  });
});