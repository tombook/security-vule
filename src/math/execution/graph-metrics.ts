/**
 * Graph Metrics Module
 * Cyclomatic complexity, centrality, reachability
 */

export interface Graph {
  nodes: string[];
  edges: Array<[string, string]>;
}

export interface CyclomaticComplexityResult {
  complexity: number;
  edges: number;
  nodes: number;
  connectedComponents: number;
}

/**
 * Calculate cyclomatic complexity M = E - N + 2P
 * E = number of edges, N = number of nodes, P = number of connected components
 */
export function cyclomaticComplexity(graph: Graph, p: number = 1): CyclomaticComplexityResult {
  const { nodes, edges } = graph;
  const e = edges.length;
  const n = nodes.length;

  // Count connected components using union-find
  const parent = new Map<string, string>();
  for (const node of nodes) parent.set(node, node);

  function find(x: string): string {
    if (parent.get(x) !== x) parent.set(x, find(parent.get(x)!));
    return parent.get(x)!;
  }

  function union(x: string, y: string): void {
    const px = find(x), py = find(y);
    if (px !== py) parent.set(px, py);
  }

  for (const [src, dst] of edges) {
    union(src, dst);
  }

  let components = 0;
  const roots = new Set<string>();
  for (const node of nodes) roots.add(find(node));
  components = roots.size;

  const m = e - n + 2 * p;

  return {
    complexity: Math.max(1, m),
    edges: e,
    nodes: n,
    connectedComponents: components
  };
}

/**
 * Calculate nesting depth of a function
 */
export function nestingDepth(ast: ASTNode): number {
  if (!ast.children || ast.children.length === 0) return 0;

  let maxDepth = 0;
  const stack: Array<{ node: ASTNode; depth: number }> = [{ node: ast, depth: 0 }];

  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    maxDepth = Math.max(maxDepth, depth);

    if (node.children) {
      for (const child of node.children) {
        stack.push({ node: child, depth: depth + 1 });
      }
    }
  }

  return maxDepth;
}

export interface ASTNode {
  type: string;
  children?: ASTNode[];
}

/**
 * Calculate degree centrality for each node
 */
export function degreeCentrality(graph: Graph): Map<string, number> {
  const centrality = new Map<string, number>();

  for (const node of graph.nodes) {
    let degree = 0;
    for (const [src, dst] of graph.edges) {
      if (src === node || dst === node) degree++;
    }
    centrality.set(node, degree);
  }

  return centrality;
}

/**
 * Calculate betweenness centrality (simplified)
 */
export function betweennessCentrality(graph: Graph): Map<string, number> {
  const centrality = new Map<string, number>();

  for (const node of graph.nodes) {
    centrality.set(node, 0);
  }

  // For each pair of nodes, find shortest paths
  for (const start of graph.nodes) {
    for (const end of graph.nodes) {
      if (start === end) continue;

      const paths = shortestPaths(graph, start, end);
      for (const path of paths) {
        for (const node of path.slice(1, -1)) {
          centrality.set(node, (centrality.get(node) || 0) + 1 / paths.length);
        }
      }
    }
  }

  return centrality;
}

/**
 * Find shortest paths using BFS
 */
function shortestPaths(graph: Graph, start: string, end: string): string[][] {
  const queue: Array<{ node: string; path: string[] }> = [{ node: start, path: [start] }];
  const visited = new Set<string>();
  const result: string[][] = [];
  let minLength = Infinity;

  while (queue.length > 0) {
    const { node, path } = queue.shift()!;

    if (path.length > minLength) continue;

    if (node === end) {
      minLength = path.length;
      result.push(path);
      continue;
    }

    visited.add(node);

    for (const [src, dst] of graph.edges) {
      if (src === node && !visited.has(dst)) {
        queue.push({ node: dst, path: [...path, dst] });
      }
    }
  }

  return result;
}

/**
 * Calculate reachability matrix
 */
export function reachability(graph: Graph): Map<string, Set<string>> {
  const reach = new Map<string, Set<string>>();

  for (const node of graph.nodes) {
    reach.set(node, new Set());
  }

  // Floyd-Warshall inspired approach
  for (const start of graph.nodes) {
    const visited = new Set<string>();
    const queue = [start];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      for (const [, dst] of graph.edges) {
        if (current === dst) continue;
      }
    }
  }

  // BFS for each node
  for (const start of graph.nodes) {
    const visited = new Set<string>();
    const queue = [start];

    while (queue.length > 0) {
      const current = queue.shift()!;

      for (const [src, dst] of graph.edges) {
        if (src === current && !visited.has(dst)) {
          visited.add(dst);
          queue.push(dst);
          reach.get(start)!.add(dst);
        }
      }
    }
  }

  return reach;
}

/**
 * Check if graph is strongly connected
 */
export function isStronglyConnected(graph: Graph): boolean {
  for (const start of graph.nodes) {
    const reachable = new Set<string>();
    const queue = [start];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (reachable.has(current)) continue;
      reachable.add(current);

      for (const [src, dst] of graph.edges) {
        if (src === current && !reachable.has(dst)) {
          queue.push(dst);
        }
      }
    }

    if (reachable.size !== graph.nodes.length) return false;
  }

  return true;
}

/**
 * CalculatePagerank for graph nodes
 */
export function pagerank(graph: Graph, damping: number = 0.85, iterations: number = 100): Map<string, number> {
  const n = graph.nodes.length;
  const ranks = new Map<string, number>();

  // Initialize
  for (const node of graph.nodes) {
    ranks.set(node, 1 / n);
  }

  // Build adjacency
  const outgoing = new Map<string, string[]>();
  const incoming = new Map<string, string[]>();

  for (const node of graph.nodes) {
    outgoing.set(node, []);
    incoming.set(node, []);
  }

  for (const [src, dst] of graph.edges) {
    outgoing.get(src)!.push(dst);
    incoming.get(dst)!.push(src);
  }

  // Iterations
  for (let iter = 0; iter < iterations; iter++) {
    const newRanks = new Map<string, number>();

    for (const node of graph.nodes) {
      let sum = 0;

      for (const neighbor of incoming.get(node) || []) {
        const outDegree = outgoing.get(neighbor)!.length;
        if (outDegree > 0) {
          sum += ranks.get(neighbor)! / outDegree;
        }
      }

      newRanks.set(node, (1 - damping) / n + damping * sum);
    }

    for (const node of graph.nodes) {
      ranks.set(node, newRanks.get(node)!);
    }
  }

  return ranks;
}