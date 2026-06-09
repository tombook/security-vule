/**
 * Program Graph Builder — Unified multi-relational code graph
 *
 * Combines AST, CFG, and DFG edges into a single graph with typed edges,
 * inspired by FUNDED_NISL's GGNN with 7 edge types (ICSE TIFS 2021).
 *
 * Edge types:
 *   AST      — parent-child syntax tree
 *   CFG      — control flow (unconditional, true, false)
 *   DFG      — data flow (def-use, parameter)
 *   CALL     — function call edges
 *   FALLS_TO — sequential statement ordering
 */

import type { ASTNode } from './parser.js';
import type { ControlFlowGraph, CFGEdge } from './cfg.js';

export type ProgramEdgeType = 'AST' | 'CFG' | 'CFG_TRUE' | 'CFG_FALSE' | 'DFG' | 'CALL' | 'FALLS_TO';

export interface PGNode {
  id: string;
  type: string;
  code?: string;
  lineStart?: number;
  lineEnd?: number;
  properties: Map<string, unknown>;
}

export interface PGEdge {
  source: string;
  target: string;
  type: ProgramEdgeType;
}

export interface ProgramGraph {
  nodes: Map<string, PGNode>;
  edges: PGEdge[];
  nodeCount: number;
  edgeCount: number;
  edgeTypeCounts: Record<ProgramEdgeType, number>;
}

let pgId = 0;
function nextId(): string { return `pg${++pgId}`; }

export function buildProgramGraph(
  ast: ASTNode,
  cfg?: ControlFlowGraph,
  code?: string,
): ProgramGraph {
  pgId = 0;

  const nodes = new Map<string, PGNode>();
  const edges: PGEdge[] = [];

  const astNodeMap = new Map<string, string>();

  buildASTNodes(ast, nodes, edges, astNodeMap, undefined);

  if (cfg) {
    addCFGEdges(cfg, nodes, edges);
  }

  addFallsToEdges(nodes, edges);

  if (code) {
    addDFGEdges(code, nodes, edges);
  }

  addCallEdges(nodes, edges);

  const edgeTypeCounts = {} as Record<ProgramEdgeType, number>;
  const types: ProgramEdgeType[] = ['AST', 'CFG', 'CFG_TRUE', 'CFG_FALSE', 'DFG', 'CALL', 'FALLS_TO'];
  for (const t of types) edgeTypeCounts[t] = 0;
  for (const e of edges) {
    if (e.type in edgeTypeCounts) edgeTypeCounts[e.type]++;
    else edgeTypeCounts[e.type] = 1;
  }

  return {
    nodes,
    edges,
    nodeCount: nodes.size,
    edgeCount: edges.length,
    edgeTypeCounts,
  };
}

function buildASTNodes(
  astNode: ASTNode,
  nodes: Map<string, PGNode>,
  edges: PGEdge[],
  astNodeMap: Map<string, string>,
  parentId?: string,
): void {
  const pgNodeId = nextId();
  astNodeMap.set(astNode.id, pgNodeId);

  const pgNode: PGNode = {
    id: pgNodeId,
    type: astNode.type,
    code: astNode.code,
    lineStart: astNode.lineNumber,
    lineEnd: astNode.endLineNumber,
    properties: new Map(astNode.properties?.entries() ?? []),
  };
  nodes.set(pgNodeId, pgNode);

  if (parentId) {
    edges.push({ source: parentId, target: pgNodeId, type: 'AST' });
  }

  if (astNode.children) {
    for (const child of astNode.children) {
      buildASTNodes(child, nodes, edges, astNodeMap, pgNodeId);
    }
  }
}

function addCFGEdges(cfg: ControlFlowGraph, nodes: Map<string, PGNode>, edges: PGEdge[]): void {
  for (const [id, cfgNode] of cfg.nodes) {
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        type: cfgNode.type,
        code: cfgNode.statements.join('\n'),
        lineStart: cfgNode.lineStart,
        lineEnd: cfgNode.lineEnd,
        properties: new Map(),
      });
    }
  }

  for (const [, cfgEdge] of cfg.edges) {
    const type = cfgEdge.type === 'true' ? 'CFG_TRUE'
      : cfgEdge.type === 'false' ? 'CFG_FALSE'
      : 'CFG';
    edges.push({ source: cfgEdge.source, target: cfgEdge.target, type });
  }
}

function addFallsToEdges(nodes: Map<string, PGNode>, edges: PGEdge[]): void {
  const byLine: Array<{ id: string; line: number }> = [];
  for (const [id, node] of nodes) {
    if (node.lineStart) {
      byLine.push({ id, line: node.lineStart });
    }
  }
  byLine.sort((a, b) => a.line - b.line);

  for (let i = 1; i < byLine.length; i++) {
    if (byLine[i].line === byLine[i - 1].line + 1) {
      edges.push({ source: byLine[i - 1].id, target: byLine[i].id, type: 'FALLS_TO' });
    }
  }
}

function addDFGEdges(code: string, nodes: Map<string, PGNode>, edges: PGEdge[]): void {
  const lines = code.split('\n');
  const defMap = new Map<string, string>();

  for (const [id, node] of nodes) {
    if (!node.code || !node.lineStart) continue;

    const defMatch = node.code.match(/(?:let|const|var|)\s*(\w+)\s*=/);
    if (defMatch) {
      defMap.set(defMatch[1], id);
    }

    const useMatches = node.code.matchAll(/\b(\w+)\b/g);
    for (const m of useMatches) {
      const varName = m[1];
      const defId = defMap.get(varName);
      if (defId && defId !== id) {
        edges.push({ source: defId, target: id, type: 'DFG' });
      }
    }
  }
}

function addCallEdges(nodes: Map<string, PGNode>, edges: PGEdge[]): void {
  const functionNodes: Array<{ id: string; name: string }> = [];
  for (const [id, node] of nodes) {
    const name = node.properties.get('name') as string | undefined;
    if (name && (node.type === 'FunctionDeclaration' || node.type === 'FunctionDef' || node.type === 'MethodDeclaration' || node.type === 'FuncDecl')) {
      functionNodes.push({ id, name });
    }
  }

  const funcMap = new Map(functionNodes.map(f => [f.name, f.id]));

  for (const [id, node] of nodes) {
    if (!node.code) continue;
    const callMatches = node.code.matchAll(/\b(\w+)\s*\(/g);
    for (const m of callMatches) {
      const calleeName = m[1];
      const calleeId = funcMap.get(calleeName);
      if (calleeId && calleeId !== id) {
        edges.push({ source: id, target: calleeId, type: 'CALL' });
      }
    }
  }
}

export function graphToAdjacencyList(graph: ProgramGraph): Map<string, Array<{ target: string; type: ProgramEdgeType }>> {
  const adj = new Map<string, Array<{ target: string; type: ProgramEdgeType }>>();
  for (const id of graph.nodes.keys()) {
    adj.set(id, []);
  }
  for (const edge of graph.edges) {
    adj.get(edge.source)?.push({ target: edge.target, type: edge.type });
  }
  return adj;
}

export function getEdgeStats(graph: ProgramGraph): string {
  return Object.entries(graph.edgeTypeCounts)
    .filter(([, count]) => count > 0)
    .map(([type, count]) => `${type}: ${count}`)
    .join(', ');
}
