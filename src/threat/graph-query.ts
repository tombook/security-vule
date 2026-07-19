/**
 * Graph Query Layer — Traversal and query algorithms over ProgramGraph
 *
 * Provides BFS, DFS, reachability, path-finding, and structural queries
 * needed by the threat model generator to identify trust boundaries,
 * attack surfaces, and data flow paths.
 */

import type { ProgramGraph, PGNode, PGEdge, ProgramEdgeType } from '../engine/program-graph.js';
import { graphToAdjacencyList } from '../engine/program-graph.js';

export class GraphQuery {
  private graph: ProgramGraph;
  private adj: Map<string, Array<{ target: string; type: ProgramEdgeType }>>;
  private reverseAdj: Map<string, Array<{ source: string; type: ProgramEdgeType }>>;

  constructor(graph: ProgramGraph) {
    this.graph = graph;
    this.adj = graphToAdjacencyList(graph);
    this.reverseAdj = this.buildReverseAdj();
  }

  bfs(start: string, edgeTypes?: ProgramEdgeType[]): Set<string> {
    const visited = new Set<string>();
    const queue = [start];
    visited.add(start);

    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const edge of this.getOutEdges(current, edgeTypes)) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          queue.push(edge.target);
        }
      }
    }
    return visited;
  }

  dfs(start: string, edgeTypes?: ProgramEdgeType[]): Set<string> {
    const visited = new Set<string>();
    this.dfsImpl(start, edgeTypes, visited);
    return visited;
  }

  reachableFrom(entryPoints: string[], edgeTypes?: ProgramEdgeType[]): Set<string> {
    const reachable = new Set<string>();
    for (const ep of entryPoints) {
      for (const node of this.bfs(ep, edgeTypes)) {
        reachable.add(node);
      }
    }
    return reachable;
  }

  findPaths(source: string, target: string, maxLength: number = 10): string[][] {
    const paths: string[][] = [];
    const current: string[] = [source];
    this.findPathsImpl(source, target, current, paths, new Set<string>([source]), maxLength);
    return paths;
  }

  shortestPath(source: string, target: string): string[] | null {
    const visited = new Set<string>([source]);
    const queue: Array<{ node: string; path: string[] }> = [{ node: source, path: [source] }];

    while (queue.length > 0) {
      const { node, path } = queue.shift()!;
      if (node === target) return path;

      for (const edge of this.getOutEdges(node)) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          queue.push({ node: edge.target, path: [...path, edge.target] });
        }
      }
    }
    return null;
  }

  nodesByType(type: string): PGNode[] {
    const result: PGNode[] = [];
    for (const [, node] of this.graph.nodes) {
      if (node.type === type) result.push(node);
    }
    return result;
  }

  filterNodes(predicate: (node: PGNode) => boolean): PGNode[] {
    const result: PGNode[] = [];
    for (const [, node] of this.graph.nodes) {
      if (predicate(node)) result.push(node);
    }
    return result;
  }

  crossingEdges(zoneA: Set<string>, zoneB: Set<string>): PGEdge[] {
    const result: PGEdge[] = [];
    for (const edge of this.graph.edges) {
      if ((zoneA.has(edge.source) && zoneB.has(edge.target)) ||
          (zoneB.has(edge.source) && zoneA.has(edge.target))) {
        result.push(edge);
      }
    }
    return result;
  }

  findEntryPoints(): PGNode[] {
    const calleeTargets = new Set<string>();
    for (const edge of this.graph.edges) {
      if (edge.type === 'CALL') calleeTargets.add(edge.target);
    }

    const functionTypes = new Set([
      'FunctionDeclaration', 'FunctionDef', 'MethodDeclaration',
      'FuncDecl', 'ArrowFunction', 'FunctionExpression',
    ]);

    return this.filterNodes(node => {
      if (!functionTypes.has(node.type)) return false;
      const name = node.properties.get('name') as string | undefined;
      if (!name) return false;

      const isHttpHandler = /^(get|post|put|delete|patch|head|options|all|use|handler|handle|process|execute|run)\b/i.test(name);
      const isEventHandler = /^(on[A-Z]|handle|process|callback)/.test(name);
      const isExported = node.properties.get('exported') === true;

      return isHttpHandler || isEventHandler || isExported || !calleeTargets.has(node.id);
    });
  }

  findNodesInScope(scopeName: string): string[] {
    const result: string[] = [];
    for (const [id, node] of this.graph.nodes) {
      const nodeScope = node.properties.get('scope') as string | undefined;
      const nodeName = node.properties.get('name') as string | undefined;
      if (nodeScope === scopeName || nodeName === scopeName) {
        result.push(id);
      }
    }
    return result;
  }

  getNode(id: string): PGNode | undefined {
    return this.graph.nodes.get(id);
  }

  getInEdges(nodeId: string, edgeTypes?: ProgramEdgeType[]): Array<{ source: string; type: ProgramEdgeType }> {
    const edges = this.reverseAdj.get(nodeId) ?? [];
    if (!edgeTypes) return edges;
    return edges.filter(e => edgeTypes.includes(e.type));
  }

  getOutEdges(nodeId: string, edgeTypes?: ProgramEdgeType[]): Array<{ target: string; type: ProgramEdgeType }> {
    const edges = this.adj.get(nodeId) ?? [];
    if (!edgeTypes) return edges;
    return edges.filter(e => edgeTypes.includes(e.type));
  }

  subgraph(nodeIds: Set<string>): { nodes: PGNode[]; edges: PGEdge[] } {
    const nodes: PGNode[] = [];
    const edges: PGEdge[] = [];

    for (const id of nodeIds) {
      const node = this.graph.nodes.get(id);
      if (node) nodes.push(node);
    }

    for (const edge of this.graph.edges) {
      if (nodeIds.has(edge.source) && nodeIds.has(edge.target)) {
        edges.push(edge);
      }
    }

    return { nodes, edges };
  }

  hasPath(source: string, target: string, edgeTypes?: ProgramEdgeType[]): boolean {
    const visited = new Set<string>();
    const queue = [source];
    visited.add(source);

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current === target) return true;

      for (const edge of this.getOutEdges(current, edgeTypes)) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          queue.push(edge.target);
        }
      }
    }
    return false;
  }

  private dfsImpl(node: string, edgeTypes: ProgramEdgeType[] | undefined, visited: Set<string>): void {
    visited.add(node);
    for (const edge of this.getOutEdges(node, edgeTypes)) {
      if (!visited.has(edge.target)) {
        this.dfsImpl(edge.target, edgeTypes, visited);
      }
    }
  }

  private findPathsImpl(
    current: string,
    target: string,
    path: string[],
    results: string[][],
    visited: Set<string>,
    maxLength: number,
  ): void {
    if (current === target) {
      results.push([...path]);
      return;
    }
    if (path.length >= maxLength) return;

    for (const edge of this.getOutEdges(current)) {
      if (!visited.has(edge.target)) {
        visited.add(edge.target);
        path.push(edge.target);
        this.findPathsImpl(edge.target, target, path, results, visited, maxLength);
        path.pop();
        visited.delete(edge.target);
      }
    }
  }

  private buildReverseAdj(): Map<string, Array<{ source: string; type: ProgramEdgeType }>> {
    const rev = new Map<string, Array<{ source: string; type: ProgramEdgeType }>>();
    for (const id of this.graph.nodes.keys()) {
      rev.set(id, []);
    }
    for (const edge of this.graph.edges) {
      rev.get(edge.target)?.push({ source: edge.source, type: edge.type });
    }
    return rev;
  }
}
