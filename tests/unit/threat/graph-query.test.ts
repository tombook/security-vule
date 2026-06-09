import { describe, test, expect } from 'bun:test';
import {
  buildProgramGraph,
  type ProgramGraph,
} from '../../../src/engine/program-graph.js';
import { GraphQuery } from '../../../src/threat/graph-query.js';
import { parsePython } from '../../../src/engine/parser.js';

function queryFromCode(code: string): { graph: ProgramGraph; query: GraphQuery } {
  const parsed = parsePython(code);
  const graph = buildProgramGraph(parsed.ast, undefined, code);
  return { graph, query: new GraphQuery(graph) };
}

describe('graph-query: GraphQuery construction', () => {
  test('constructs from program graph', () => {
    const code = `x = 1\ny = 2`;
    const { query } = queryFromCode(code);
    expect(query).toBeDefined();
  });
});

describe('graph-query: bfs / dfs', () => {
  test('bfs returns reachable set', () => {
    const code = `x = 1\ny = 2\nz = x + y`;
    const { query, graph } = queryFromCode(code);
    const allNodes = Array.from(graph.nodes.keys());
    if (allNodes.length > 0) {
      const visited = query.bfs(allNodes[0]);
      expect(visited).toBeInstanceOf(Set);
      expect(visited.size).toBeGreaterThan(0);
    }
  });

  test('dfs returns reachable set', () => {
    const code = `x = 1\ny = 2`;
    const { query, graph } = queryFromCode(code);
    const allNodes = Array.from(graph.nodes.keys());
    if (allNodes.length > 0) {
      const visited = query.dfs(allNodes[0]);
      expect(visited).toBeInstanceOf(Set);
    }
  });

  test('bfs with edge type filter', () => {
    const code = `x = 1\ny = x + 1`;
    const { query, graph } = queryFromCode(code);
    const allNodes = Array.from(graph.nodes.keys());
    if (allNodes.length > 0) {
      const visited = query.bfs(allNodes[0], ['AST']);
      expect(visited).toBeInstanceOf(Set);
    }
  });
});

describe('graph-query: reachableFrom', () => {
  test('returns union of BFS from multiple entry points', () => {
    const code = `x = 1\ny = 2\nz = 3`;
    const { query, graph } = queryFromCode(code);
    const nodes = Array.from(graph.nodes.keys());
    if (nodes.length >= 2) {
      const reachable = query.reachableFrom([nodes[0], nodes[1]]);
      expect(reachable).toBeInstanceOf(Set);
      expect(reachable.has(nodes[0])).toBe(true);
      expect(reachable.has(nodes[1])).toBe(true);
    }
  });
});

describe('graph-query: findPaths / shortestPath / hasPath', () => {
  test('hasPath returns boolean', () => {
    const code = `x = 1\ny = 2`;
    const { query, graph } = queryFromCode(code);
    const nodes = Array.from(graph.nodes.keys());
    if (nodes.length >= 2) {
      const has = query.hasPath(nodes[0], nodes[1]);
      expect(typeof has).toBe('boolean');
    }
  });

  test('findPaths returns array', () => {
    const code = `x = 1\ny = 2`;
    const { query, graph } = queryFromCode(code);
    const nodes = Array.from(graph.nodes.keys());
    if (nodes.length >= 2) {
      const paths = query.findPaths(nodes[0], nodes[1]);
      expect(paths).toBeArray();
    }
  });

  test('shortestPath returns array or null', () => {
    const code = `x = 1\ny = 2`;
    const { query, graph } = queryFromCode(code);
    const nodes = Array.from(graph.nodes.keys());
    if (nodes.length >= 2) {
      const sp = query.shortestPath(nodes[0], nodes[1]);
      expect(sp === null || Array.isArray(sp)).toBe(true);
    }
  });
});

describe('graph-query: nodesByType / filterNodes / getNode', () => {
  test('nodesByType returns matching nodes', () => {
    const code = `x = 1\ny = 2`;
    const { query } = queryFromCode(code);
    const nodes = query.nodesByType('identifier');
    expect(nodes).toBeArray();
  });

  test('filterNodes with predicate', () => {
    const code = `x = 1\ny = 2`;
    const { query } = queryFromCode(code);
    const all = query.filterNodes(n => n.type === 'identifier');
    expect(all).toBeArray();
  });

  test('getNode returns node or undefined', () => {
    const code = `x = 1`;
    const { query, graph } = queryFromCode(code);
    const firstNode = Array.from(graph.nodes.values())[0];
    if (firstNode) {
      const n = query.getNode(firstNode.id);
      expect(n).toBeDefined();
    }
    const missing = query.getNode('nonexistent_id_xyz');
    expect(missing).toBeUndefined();
  });
});

describe('graph-query: edges / adjacency', () => {
  test('getOutEdges returns array', () => {
    const code = `x = 1\ny = 2`;
    const { query, graph } = queryFromCode(code);
    const firstNode = Array.from(graph.nodes.values())[0];
    if (firstNode) {
      const edges = query.getOutEdges(firstNode.id);
      expect(edges).toBeArray();
    }
  });

  test('getInEdges returns array', () => {
    const code = `x = 1\ny = 2`;
    const { query, graph } = queryFromCode(code);
    const firstNode = Array.from(graph.nodes.values())[0];
    if (firstNode) {
      const edges = query.getInEdges(firstNode.id);
      expect(edges).toBeArray();
    }
  });

  test('subgraph returns nodes and edges', () => {
    const code = `x = 1\ny = 2\nz = 3`;
    const { query, graph } = queryFromCode(code);
    const allNodes = new Set(Array.from(graph.nodes.keys()).slice(0, 2));
    const sg = query.subgraph(allNodes);
    expect(sg.nodes).toBeArray();
    expect(sg.edges).toBeArray();
  });
});

describe('graph-query: structural', () => {
  test('findEntryPoints returns array', () => {
    const code = `def main(): pass`;
    const { query } = queryFromCode(code);
    const entries = query.findEntryPoints();
    expect(entries).toBeArray();
  });

  test('findNodesInScope returns string array', () => {
    const code = `x = 1`;
    const { query } = queryFromCode(code);
    const nodes = query.findNodesInScope('global');
    expect(nodes).toBeArray();
  });

  test('crossingEdges returns array', () => {
    const code = `x = 1\ny = 2`;
    const { query, graph } = queryFromCode(code);
    const allNodes = Array.from(graph.nodes.keys());
    if (allNodes.length >= 2) {
      const zoneA = new Set([allNodes[0]]);
      const zoneB = new Set([allNodes[1]]);
      const crossing = query.crossingEdges(zoneA, zoneB);
      expect(crossing).toBeArray();
    }
  });
});
