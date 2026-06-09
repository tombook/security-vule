/**
 * Code Property Graph (CPG) — unified data substrate for cosmic-galaxy
 * dimension detectors.
 *
 * Aligns with cosmic-galaxy's NetworkX DiGraph metaphor:
 *   - CPGNode  ≈  graph vertex (code node)
 *   - CPGEdge  ≈  typed relation (DATA_FLOW, CONTROL_FLOW, CALL, ...)
 *   - CPG      ≈  DiGraph with rich query methods
 *
 * Five edge kinds (matches cosmic-galaxy's mappings.yaml):
 *   data      — taint propagation (variable → sink)
 *   control   — control flow (stmt → stmt)
 *   call      — caller → callee (function)
 *   def_use   — definition → use (variable binding)
 *   ast_child — parent → child in AST
 *
 * Spec: docs/superpowers/specs/2026-06-10-cosmic-galaxy-evolution-design.md §2.3
 */

export type CPGNodeType = 'stmt' | 'expr' | 'func' | 'var';

export type CPGLanguage = 'php' | 'python' | 'javascript' | 'typescript';

export interface CPGNode {
  id: string;
  type: CPGNodeType;
  file: string;
  line: number;
  col: number;
  code: string;
  language: CPGLanguage;
  features: Record<string, number>;
}

export type CPGEdgeKind = 'data' | 'control' | 'call' | 'def_use' | 'ast_child';

export interface CPGEdge {
  source: string;
  target: string;
  kind: CPGEdgeKind;
  weight?: number;
}

export interface CPG {
  nodes: Map<string, CPGNode>;
  edges: CPGEdge[];
  language: CPGLanguage;

  getNode(id: string): CPGNode | undefined;
  outEdges(id: string, kind?: CPGEdgeKind): CPGEdge[];
  inEdges(id: string, kind?: CPGEdgeKind): CPGEdge[];
  shortestPath(from: string, to: string): string[] | null;
  sinkNodes(): CPGNode[];
  sourcesFor(sinkId: string): CPGNode[];
  functions(): CPGNode[];
  callGraph(callee: string): string[];
  inDegree(id: string): number;
  outDegree(id: string): number;
}