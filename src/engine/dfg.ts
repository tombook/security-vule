// Data Flow Graph construction for white-box analysis
import type { CPGNode, CPGEdge, CodePropertyGraph } from '../math/cpg.js';

export interface DFGNode {
  id: string;
  type: 'definition' | 'use' | 'parameter' | 'return' | 'import';
  name: string;
  scope: string;
  line: number;
}

export interface DFGEdge {
  from: string;
  to: string;
  type: 'def-use' | 'param-pass' | 'return-flow' | 'alias';
  value?: string;
}

export interface DataFlowResult {
  nodes: DFGNode[];
  edges: DFGEdge[];
  reachingDefs: Map<string, string[]>;
  liveVars: Map<string, Set<string>>;
}

// Reaching definitions analysis
export function reachingDefinitions(cpg: CodePropertyGraph, functionName: string): Map<string, string[]> {
  const defs = new Map<string, string[]>();
  
  for (const [id, node] of cpg.nodes) {
    if (node.name === functionName || (node.properties.get('functionName') as string) === functionName) {
      if (node.type === 'Statement' && node.code) {
        const defMatches = node.code.matchAll(/(?:let|const|var)?\s*(\w+)\s*=/g);
        for (const match of defMatches) {
          const varName = match[1];
          const existing = defs.get(varName) || [];
          existing.push(id);
          defs.set(varName, existing);
        }
      }
    }
  }
  
  return defs;
}

// Live variable analysis
export function liveVariableAnalysis(cpg: CodePropertyGraph, functionName: string): Map<string, Set<string>> {
  const live = new Map<string, Set<string>>();
  
  for (const [id, node] of cpg.nodes) {
    if ((node.name === functionName || (node.properties.get('functionName') as string) === functionName) && node.type === 'Expression') {
      if (node.code) {
        const varMatches = node.code.matchAll(/\b(\w+)\b/g);
        const vars = new Set<string>();
        for (const _match of varMatches) {
          vars.add(_match[1]);
        }
        if (vars.size > 0) {
          live.set(id, vars);
        }
      }
    }
  }
  
  return live;
}

// Build DFG from CPG
export function buildDFG(cpg: CodePropertyGraph, functionName: string): DataFlowResult {
  const reachingDefs = reachingDefinitions(cpg, functionName);
  const liveVars = liveVariableAnalysis(cpg, functionName);
  
  const dfgNodes: DFGNode[] = [];
  const dfgEdges: DFGEdge[] = [];
  
  // Build DFG nodes from CPG
  for (const [id, node] of cpg.nodes) {
    if (node.name === functionName || (node.properties.get('functionName') as string) === functionName) {
      if (node.type === 'Statement' || node.type === 'Expression') {
        dfgNodes.push({
          id,
          type: node.type === 'Statement' ? 'definition' : 'use',
          name: node.code || '',
          scope: functionName,
          line: node.lineNumber || 0
        });
      }
    }
  }
  
  // Build DFG edges from CFG data flow
  for (const [id, edge] of cpg.edges) {
    if (edge.type === 'CFG') {
      dfgEdges.push({
        from: edge.source,
        to: edge.target,
        type: 'def-use'
      });
    }
  }
  
  return { nodes: dfgNodes, edges: dfgEdges, reachingDefs, liveVars };
}

// Forward data flow analysis
export function forwardAnalysis(cpg: CodePropertyGraph, startNode: string): Set<string> {
  const reachable = new Set<string>();
  const queue = [startNode];
  
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (reachable.has(current)) continue;
    reachable.add(current);
    
    for (const [id, edge] of cpg.edges) {
      if (edge.source === current && edge.type === 'CFG') {
        queue.push(edge.target);
      }
    }
  }
  
  return reachable;
}

// Backward data flow analysis  
export function backwardAnalysis(cpg: CodePropertyGraph, endNode: string): Set<string> {
  const reachable = new Set<string>();
  const queue = [endNode];
  
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (reachable.has(current)) continue;
    reachable.add(current);
    
    for (const [id, edge] of cpg.edges) {
      if (edge.target === current && edge.type === 'CFG') {
        queue.push(edge.source);
      }
    }
  }
  
  return reachable;
}

// Alias analysis (simplified)
export function aliasAnalysis(cpg: CodePropertyGraph, var1: string, var2: string): boolean {
  if (var1 === var2) return true;
  
  for (const [id, node] of cpg.nodes) {
    if (node.code) {
      if (node.code.includes(var1) && node.code.includes(var2)) return true;
    }
  }
  
  return false;
}

