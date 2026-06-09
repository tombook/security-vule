/**
 * CPGBuilder — converts existing ProgramGraph (AST+CFG+DFG+CALL+FALLS_TO)
 * into the unified CPG with five cosmic-galaxy-aligned edge kinds.
 *
 * Maps ProgramGraph edges:
 *   AST        → ast_child
 *   CFG        → control
 *   CFG_TRUE   → control (weight: 0.5)
 *   CFG_FALSE  → control (weight: 0.5)
 *   DFG        → data
 *   CALL       → call
 *   FALLS_TO   → control
 *
 * Spec: docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md §2.4
 */

import type { ProgramGraph, ProgramEdgeType, PGNode } from '../program-graph.js';
import type { CPG, CPGNode, CPGNodeType, CPGLanguage, CPGEdge, CPGEdgeKind } from './types.js';
import { isSinkFunction } from './sinks.js';

const EDGE_KIND_MAP: Record<ProgramEdgeType, CPGEdgeKind> = {
  'AST': 'ast_child',
  'CFG': 'control',
  'CFG_TRUE': 'control',
  'CFG_FALSE': 'control',
  'DFG': 'data',
  'CALL': 'call',
  'FALLS_TO': 'control',
};

function classifyNodeType(pgNode: PGNode): CPGNodeType {
  const t = pgNode.type.toLowerCase();
  if (t === 'function_definition' || t === 'method_declaration' || t.includes('function')) return 'func';
  if (t === 'variable' || t === 'identifier' || t === 'name') return 'var';
  if (t === 'call' || t === 'call_expression' || t === 'invocation') return 'stmt';
  return 'stmt';
}

export class CPGBuilder {
  constructor(private language: CPGLanguage, private filePath: string = '') {}

  build(pg: ProgramGraph): CPG {
    const nodes = new Map<string, CPGNode>();
    const edges: CPGEdge[] = [];

    for (const [id, pn] of pg.nodes) {
      const features: Record<string, number> = {};
      for (const [k, v] of pn.properties) {
        if (typeof v === 'number') features[k] = v;
      }
      const callName = extractCallName(pn.code);
      if (callName && isSinkFunction(callName, this.language)) {
        features['is_sink'] = 1;
      }
      nodes.set(id, {
        id,
        type: classifyNodeType(pn),
        file: this.filePath,
        line: pn.lineStart || 0,
        col: 0,
        code: pn.code || '',
        language: this.language,
        features,
      });
    }

    for (const e of pg.edges) {
      const kind = EDGE_KIND_MAP[e.type];
      if (!kind) continue;
      edges.push({ source: e.source, target: e.target, kind });
    }

    return createCPG(nodes, edges, this.language);
  }
}

function extractCallName(code: string | undefined): string | null {
  if (!code) return null;
  const m = code.match(/^\s*([A-Za-z_][\w$]*)\s*\(/);
  return m ? m[1] : null;
}

export function createCPG(
  nodes: Map<string, CPGNode>,
  edges: CPGEdge[],
  language: CPGLanguage,
): CPG {
  const outIndex = new Map<string, CPGEdge[]>();
  const inIndex = new Map<string, CPGEdge[]>();
  for (const e of edges) {
    if (!outIndex.has(e.source)) outIndex.set(e.source, []);
    if (!inIndex.has(e.target)) inIndex.set(e.target, []);
    outIndex.get(e.source)!.push(e);
    inIndex.get(e.target)!.push(e);
  }

  const adjList = new Map<string, string[]>();
  for (const e of edges) {
    if (!adjList.has(e.source)) adjList.set(e.source, []);
    adjList.get(e.source)!.push(e.target);
  }

  function shortestPath(from: string, to: string): string[] | null {
    if (from === to) return [from];
    const visited = new Set<string>([from]);
    const queue: Array<{ node: string; path: string[] }> = [{ node: from, path: [from] }];
    while (queue.length) {
      const { node, path } = queue.shift()!;
      const neighbors = adjList.get(node) || [];
      for (const n of neighbors) {
        if (visited.has(n)) continue;
        const newPath = [...path, n];
        if (n === to) return newPath;
        visited.add(n);
        queue.push({ node: n, path: newPath });
      }
    }
    return null;
  }

  return {
    nodes,
    edges,
    language,
    getNode: (id) => nodes.get(id),
    outEdges: (id, kind) => (outIndex.get(id) || []).filter(e => !kind || e.kind === kind),
    inEdges: (id, kind) => (inIndex.get(id) || []).filter(e => !kind || e.kind === kind),
    shortestPath,
    sinkNodes: () => Array.from(nodes.values()).filter(n => n.features['is_sink'] === 1),
    sourcesFor: (sinkId) => {
      const result: CPGNode[] = [];
      const visited = new Set<string>();
      const queue = [sinkId];
      while (queue.length) {
        const cur = queue.shift()!;
        if (visited.has(cur)) continue;
        visited.add(cur);
        for (const e of inIndex.get(cur) || []) {
          if (e.kind === 'data') {
            const src = nodes.get(e.source);
            if (src) result.push(src);
            queue.push(e.source);
          }
        }
      }
      return result;
    },
    functions: () => Array.from(nodes.values()).filter(n => n.type === 'func'),
    callGraph: (callee) => {
      const callers: string[] = [];
      for (const e of edges) {
        if (e.kind === 'call' && e.target === callee) callers.push(e.source);
      }
      return callers;
    },
    inDegree: (id) => (inIndex.get(id) || []).length,
    outDegree: (id) => (outIndex.get(id) || []).length,
  };
}