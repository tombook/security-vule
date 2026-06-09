/**
 * Code Property Graph (CPG) Representation Module
 */

// Node types
export type CPGNodeType =
  | 'File'
  | 'Function'
  | 'Block'
  | 'Statement'
  | 'Expression'
  | 'Type'
  | 'Literal';

export interface CPGNode {
  id: string;
  type: CPGNodeType;
  name?: string;
  code?: string;
  lineNumber?: number;
  properties: Map<string, unknown>;
}

// Edge types
export type CPGEdgeType =
  | 'AST'
  | 'CFG'
  | 'CALL'
  | 'SOURCE'
  | 'SINK'
  | 'DATA_FLOW'
  | 'CONTROL_FLOW';

export interface CPGEdge {
  source: string;
  target: string;
  type: CPGEdgeType;
  properties?: Map<string, unknown>;
}

// CPG structure
export interface CodePropertyGraph {
  nodes: Map<string, CPGNode>;
  edges: Map<string, CPGEdge>;
  metadata: CPGMetadata;
}

export interface CPGMetadata {
  language?: string;
  projectPath?: string;
  createdAt?: Date;
  version?: string;
}

// Builder for CPG
export class CPGBuilder {
  private nodes: Map<string, CPGNode> = new Map();
  private edges: Map<string, CPGEdge> = new Map();
  private metadata: CPGMetadata = {};

  setLanguage(lang: string): this {
    this.metadata.language = lang;
    return this;
  }

  setProjectPath(path: string): this {
    this.metadata.projectPath = path;
    return this;
  }

  addFile(id: string, name: string, code?: string): this {
    this.nodes.set(id, {
      id,
      type: 'File',
      name,
      code,
      properties: new Map()
    });
    return this;
  }

  addFunction(id: string, name: string, lineNumber?: number): this {
    this.nodes.set(id, {
      id,
      type: 'Function',
      name,
      lineNumber,
      properties: new Map()
    });
    return this;
  }

  addBlock(id: string, name?: string): this {
    this.nodes.set(id, {
      id,
      type: 'Block',
      name,
      properties: new Map()
    });
    return this;
  }

  addStatement(id: string, code: string, lineNumber?: number): this {
    this.nodes.set(id, {
      id,
      type: 'Statement',
      code,
      lineNumber,
      properties: new Map()
    });
    return this;
  }

  addExpression(id: string, code: string, lineNumber?: number): this {
    this.nodes.set(id, {
      id,
      type: 'Expression',
      code,
      lineNumber,
      properties: new Map()
    });
    return this;
  }

  addType(id: string, name: string): this {
    this.nodes.set(id, {
      id,
      type: 'Type',
      name,
      properties: new Map()
    });
    return this;
  }

  addLiteral(id: string, value: string, type?: string): this {
    this.nodes.set(id, {
      id,
      type: 'Literal',
      code: value,
      name: type,
      properties: new Map([['value', value]])
    });
    return this;
  }

  addASTEdge(source: string, target: string): this {
    this.edges.set(`${source}->${target}`, {
      source,
      target,
      type: 'AST',
      properties: new Map()
    });
    return this;
  }

  addCFGEdge(source: string, target: string): this {
    this.edges.set(`${source}->${target}`, {
      source,
      target,
      type: 'CFG',
      properties: new Map()
    });
    return this;
  }

  addCallEdge(source: string, target: string): this {
    this.edges.set(`${source}->${target}`, {
      source,
      target,
      type: 'CALL',
      properties: new Map()
    });
    return this;
  }

  addSourceEdge(source: string, target: string): this {
    this.edges.set(`${source}->${target}`, {
      source,
      target,
      type: 'SOURCE',
      properties: new Map()
    });
    return this;
  }

  addSinkEdge(source: string, target: string): this {
    this.edges.set(`${source}->${target}`, {
      source,
      target,
      type: 'SINK',
      properties: new Map()
    });
    return this;
  }

  addDataFlowEdge(source: string, target: string): this {
    this.edges.set(`${source}->${target}`, {
      source,
      target,
      type: 'DATA_FLOW',
      properties: new Map()
    });
    return this;
  }

  addControlFlowEdge(source: string, target: string): this {
    this.edges.set(`${source}->${target}`, {
      source,
      target,
      type: 'CONTROL_FLOW',
      properties: new Map()
    });
    return this;
  }

  build(): CodePropertyGraph {
    return {
      nodes: this.nodes,
      edges: this.edges,
      metadata: { ...this.metadata, createdAt: new Date() }
    };
  }
}

// Query functions
export function getNodesByType(cpg: CodePropertyGraph, type: CPGNodeType): CPGNode[] {
  const result: CPGNode[] = [];
  for (const node of cpg.nodes.values()) {
    if (node.type === type) result.push(node);
  }
  return result;
}

export function getEdgesByType(cpg: CodePropertyGraph, type: CPGEdgeType): CPGEdge[] {
  const result: CPGEdge[] = [];
  for (const edge of cpg.edges.values()) {
    if (edge.type === type) result.push(edge);
  }
  return result;
}

export function getOutgoingEdges(cpg: CodePropertyGraph, nodeId: string): CPGEdge[] {
  const result: CPGEdge[] = [];
  for (const edge of cpg.edges.values()) {
    if (edge.source === nodeId) result.push(edge);
  }
  return result;
}

export function getIncomingEdges(cpg: CodePropertyGraph, nodeId: string): CPGEdge[] {
  const result: CPGEdge[] = [];
  for (const edge of cpg.edges.values()) {
    if (edge.target === nodeId) result.push(edge);
  }
  return result;
}

export function findNodesByName(cpg: CodePropertyGraph, name: string): CPGNode[] {
  const result: CPGNode[] = [];
  for (const node of cpg.nodes.values()) {
    if (node.name === name) result.push(node);
  }
  return result;
}

export function getCallGraph(cpg: CodePropertyGraph): Map<string, string[]> {
  const calls = new Map<string, string[]>();

  for (const edge of cpg.edges.values()) {
    if (edge.type === 'CALL') {
      const existing = calls.get(edge.source) || [];
      existing.push(edge.target);
      calls.set(edge.source, existing);
    }
  }

  return calls;
}

export function getDataFlowPaths(cpg: CodePropertyGraph): Array<Array<string>> {
  const paths: Array<Array<string>> = [];

  for (const edge of cpg.edges.values()) {
    if (edge.type === 'SOURCE') {
      // Find paths from source to sink
      const visited = new Set<string>();
      const path = [edge.source];

      function dfs(current: string, path: string[]): void {
        if (visited.has(current)) return;
        visited.add(current);

        for (const e of cpg.edges.values()) {
          if (e.source === current && e.type === 'SINK') {
            paths.push([...path, e.target]);
          } else if (e.source === current && (e.type === 'DATA_FLOW' || e.type === 'CFG')) {
            dfs(e.target, [...path, e.target]);
          }
        }
      }

      dfs(edge.target, [edge.source, edge.target]);
    }
  }

  return paths;
}

export function getFunctionCFG(cpg: CodePropertyGraph, functionId: string): string[] {
  const cfgNodes: string[] = [functionId];

  function collectCFG(nodeId: string): void {
    for (const edge of cpg.edges.values()) {
      if (edge.source === nodeId && edge.type === 'CFG') {
        if (!cfgNodes.includes(edge.target)) {
          cfgNodes.push(edge.target);
          collectCFG(edge.target);
        }
      }
    }
  }

  collectCFG(functionId);
  return cfgNodes;
}