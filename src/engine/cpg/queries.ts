/**
 * CPG queries — BFS, DFS, allPaths, downstream/upstream traversal.
 * Used by dimension detectors (e.g., 引力场 uses downstreamNodes to find sinks).
 *
 * Spec: §2.3 "高级查询"
 */

import type { CPG } from './types.js';

export function bfs(cpg: CPG, start: string): string[] {
  const visited = new Set<string>([start]);
  const queue = [start];
  const result: string[] = [];
  while (queue.length) {
    const cur = queue.shift()!;
    result.push(cur);
    for (const e of cpg.outEdges(cur)) {
      if (!visited.has(e.target)) {
        visited.add(e.target);
        queue.push(e.target);
      }
    }
  }
  return result;
}

export function dfs(cpg: CPG, start: string): string[] {
  const visited = new Set<string>();
  const result: string[] = [];
  function recurse(node: string): void {
    if (visited.has(node)) return;
    visited.add(node);
    result.push(node);
    for (const e of cpg.outEdges(node)) recurse(e.target);
  }
  recurse(start);
  return result;
}

export function downstreamNodes(cpg: CPG, start: string): string[] {
  const visited = new Set<string>();
  const queue = [start];
  const result: string[] = [];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of cpg.outEdges(cur)) {
      if (!visited.has(e.target)) {
        visited.add(e.target);
        result.push(e.target);
        queue.push(e.target);
      }
    }
  }
  return result;
}

export function upstreamNodes(cpg: CPG, start: string): string[] {
  const visited = new Set<string>();
  const queue = [start];
  const result: string[] = [];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of cpg.inEdges(cur)) {
      if (!visited.has(e.source)) {
        visited.add(e.source);
        result.push(e.source);
        queue.push(e.source);
      }
    }
  }
  return result;
}

export function allPaths(cpg: CPG, from: string, to: string, maxPaths = 100): string[][] {
  const paths: string[][] = [];
  const stack: Array<{ node: string; path: string[] }> = [{ node: from, path: [from] }];
  while (stack.length && paths.length < maxPaths) {
    const { node, path } = stack.pop()!;
    if (node === to && path.length > 1) {
      paths.push(path);
      continue;
    }
    for (const e of cpg.outEdges(node)) {
      if (!path.includes(e.target)) {
        stack.push({ node: e.target, path: [...path, e.target] });
      }
    }
  }
  return paths;
}