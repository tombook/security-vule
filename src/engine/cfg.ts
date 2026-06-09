/**
 * Control Flow Graph (CFG) Construction Module
 * Features: Basic block identification, dominator tree, loop detection
 */

import type { ASTNode } from './parser.js';

// CFG node types
export type CFGNodeType = 
  | 'entry' 
  | 'exit' 
  | 'block' 
  | 'conditional' 
  | 'jump' 
  | 'return';

export interface CFGNode {
  id: string;
  type: CFGNodeType;
  statements: string[];
  lineStart?: number;
  lineEnd?: number;
}

// CFG edge types
export type CFGEdgeType = 'unconditional' | 'true' | 'false' | 'fallthrough';

export interface CFGEdge {
  source: string;
  target: string;
  type: CFGEdgeType;
}

// CFG structure
export interface ControlFlowGraph {
  nodes: Map<string, CFGNode>;
  edges: Map<string, CFGEdge>;
  entryId: string;
  exitId: string;
}

// Dominator tree node
export interface DominatorNode {
  id: string;
  dominatorOf: Set<string>;
  dominatedBy: Set<string>;
  immediateDominator?: string;
}

// Simple ID generator
let cfgNodeCounter = 0;
function generateCFGId(): string {
  return `cfg${++cfgNodeCounter}`;
}

/**
 * Build CFG from AST
 */
export function buildCFG(ast: ASTNode): ControlFlowGraph {
  cfgNodeCounter = 0;
  
  const cfg: ControlFlowGraph = {
    nodes: new Map(),
    edges: new Map(),
    entryId: generateCFGId(),
    exitId: generateCFGId()
  };

  // Create entry and exit nodes
  cfg.nodes.set(cfg.entryId, {
    id: cfg.entryId,
    type: 'entry',
    statements: []
  });

  cfg.nodes.set(cfg.exitId, {
    id: cfg.exitId,
    type: 'exit',
    statements: []
  });

  // Build CFG from AST
  const blocks = identifyBasicBlocks(ast);
  
  // Create CFG nodes for each basic block
  const blockIds: string[] = [];
  for (const block of blocks) {
    const nodeId = generateCFGId();
    blockIds.push(nodeId);
    
    cfg.nodes.set(nodeId, {
      id: nodeId,
      type: 'block',
      statements: block.statements,
      lineStart: block.lineStart,
      lineEnd: block.lineEnd
    });
  }

  // Connect blocks with edges
  for (let i = 0; i < blockIds.length; i++) {
    const currentId = blockIds[i];
    const nextId = i + 1 < blockIds.length ? blockIds[i + 1] : cfg.exitId;
    
    cfg.edges.set(`${currentId}->${nextId}`, {
      source: currentId,
      target: nextId,
      type: 'unconditional'
    });

    // Check if current block ends with a conditional jump
    const currentNode = cfg.nodes.get(currentId);
    if (currentNode && currentNode.statements.length > 0) {
      const lastStmt = currentNode.statements[currentNode.statements.length - 1];
      
      if (lastStmt.startsWith('if ') || lastStmt.startsWith('for ') || 
          lastStmt.startsWith('while ') || lastStmt.startsWith('if(')) {
        // For conditionals, also add fallthrough edge (handled above)
      }
    }
  }

  // Connect entry to first block
  if (blockIds.length > 0) {
    cfg.edges.set(`${cfg.entryId}->${blockIds[0]}`, {
      source: cfg.entryId,
      target: blockIds[0],
      type: 'unconditional'
    });
  } else {
    cfg.edges.set(`${cfg.entryId}->${cfg.exitId}`, {
      source: cfg.entryId,
      target: cfg.exitId,
      type: 'unconditional'
    });
  }

  return cfg;
}

/**
 * Identify basic blocks from AST
 */
export interface BasicBlock {
  statements: string[];
  lineStart?: number;
  lineEnd?: number;
  isLoopHeader?: boolean;
  isConditional?: boolean;
}

function identifyBasicBlocks(ast: ASTNode): BasicBlock[] {
  const blocks: BasicBlock[] = [];
  const statements: string[] = [];
  let currentLineStart: number | undefined;
  let currentLineEnd: number | undefined;

  function flushBlock(isLoopHeader = false, isConditional = false): void {
    if (statements.length > 0) {
      blocks.push({
        statements: [...statements],
        lineStart: currentLineStart,
        lineEnd: currentLineEnd,
        isLoopHeader,
        isConditional
      });
      statements.length = 0;
      currentLineStart = undefined;
      currentLineEnd = undefined;
    }
  }

  function traverse(node: ASTNode): void {
    if (node.code) {
      const line = node.code.trim();
      
      if (!currentLineStart && node.lineNumber) {
        currentLineStart = node.lineNumber;
      }
      if (node.lineNumber) {
        currentLineEnd = node.lineNumber;
      }

      // Check for loop/conditional headers
      const isLoopHeader = node.type === 'Loop' || 
        line.startsWith('for ') || line.startsWith('while ');
      const isConditional = node.type === 'If' || node.type === 'IfStatement' ||
        line.startsWith('if ') || line.startsWith('if(');

      // Start a new block after unconditional jumps
      if (isLoopHeader || isConditional) {
        flushBlock(isLoopHeader, isConditional);
      }

      statements.push(line);
    }

    node.children?.forEach(traverse);
  }

  traverse(ast);
  flushBlock();

  return blocks;
}

/**
 * Compute immediate dominators using the algorithm from the AST
 */
export function computeDominators(cfg: ControlFlowGraph): Map<string, DominatorNode> {
  const dominators = new Map<string, DominatorNode>();
  
  // Initialize
  for (const nodeId of cfg.nodes.keys()) {
    dominators.set(nodeId, {
      id: nodeId,
      dominatorOf: new Set([nodeId]),
      dominatedBy: new Set()
    });
  }

  // Entry dominates itself
  const entryDominators = dominators.get(cfg.entryId)!;
  entryDominators.dominatorOf = new Set(cfg.nodes.keys());

  // Iterative fixpoint computation (simplified)
  let changed = true;
  let iterations = 0;
  const maxIterations = cfg.nodes.size * 2;

  while (changed && iterations < maxIterations) {
    changed = false;
    iterations++;

    for (const [nodeId, node] of cfg.nodes.entries()) {
      if (nodeId === cfg.entryId) continue;

      // Get predecessors
      const predecessors = getPredecessors(cfg, nodeId);
      if (predecessors.length === 0) continue;

      // New dominators = intersection of predecessors' dominators + self
      let newDomSet = new Set<string>([nodeId]);
      
      for (const pred of predecessors) {
        const predDom = dominators.get(pred);
        if (predDom) {
          newDomSet = intersection(newDomSet, new Set([...predDom.dominatorOf, pred]));
        }
      }

      const domNode = dominators.get(nodeId)!;
      if (!setsEqual(domNode.dominatorOf, newDomSet)) {
        domNode.dominatorOf = newDomSet;
        changed = true;
      }
    }
  }

  // Compute immediate dominators and dominatedBy relationships
  for (const [nodeId, domNode] of dominators.entries()) {
    if (nodeId === cfg.entryId) continue;

    // Find immediate dominator (strict dominator that doesn't dominate any other strict dominator)
    const strictDoms = new Set([...domNode.dominatorOf].filter(id => id !== nodeId));
    
    let immediateDom: string | undefined;
    for (const candidate of strictDoms) {
      let isImmediate = true;
      for (const other of strictDoms) {
        if (other !== candidate && dominators.get(other)?.dominatorOf.has(candidate)) {
          isImmediate = false;
          break;
        }
      }
      if (isImmediate) {
        immediateDom = candidate;
        break;
      }
    }

    domNode.immediateDominator = immediateDom;
    
    // Update dominatedBy
    if (immediateDom) {
      const immDomNode = dominators.get(immediateDom);
      if (immDomNode) {
        immDomNode.dominatedBy.add(nodeId);
      }
    }
  }

  return dominators;
}

function getPredecessors(cfg: ControlFlowGraph, nodeId: string): string[] {
  const preds: string[] = [];
  for (const edge of cfg.edges.values()) {
    if (edge.target === nodeId) {
      preds.push(edge.source);
    }
  }
  return preds;
}

function intersection(set1: Set<string>, set2: Set<string>): Set<string> {
  const result = new Set<string>();
  for (const item of set1) {
    if (set2.has(item)) {
      result.add(item);
    }
  }
  return result;
}

function setsEqual(set1: Set<string>, set2: Set<string>): boolean {
  if (set1.size !== set2.size) return false;
  for (const item of set1) {
    if (!set2.has(item)) return false;
  }
  return true;
}

/**
 * Detect loops in CFG
 */
export interface LoopInfo {
  header: string;
  body: Set<string>;
  preHeader?: string;
  backEdges: Array<{ from: string; to: string }>;
}

export function detectLoops(cfg: ControlFlowGraph): LoopInfo[] {
  const loops: LoopInfo[] = [];
  const dominators = computeDominators(cfg);

  // Find back edges (edges where target dominates source)
  const backEdges: Array<{ from: string; to: string }> = [];
  
  for (const edge of cfg.edges.values()) {
    const sourceDom = dominators.get(edge.source);
    const targetDom = dominators.get(edge.target);
    
    if (sourceDom && targetDom && targetDom.dominatorOf.has(edge.source)) {
      backEdges.push({ from: edge.source, to: edge.target });
    }
  }

  // Group back edges by header to identify loops
  const loopsByHeader = new Map<string, Set<string>>();
  
  for (const backEdge of backEdges) {
    const header = backEdge.to;
    if (!loopsByHeader.has(header)) {
      loopsByHeader.set(header, new Set([header]));
    }
    loopsByHeader.get(header)!.add(backEdge.from);
  }

  // Expand loop bodies
  for (const [header, body] of loopsByHeader.entries()) {
    // Find all nodes that can reach the header without passing through the header
    const expandedBody = new Set(body);
    let changed = true;
    
    while (changed) {
      changed = false;
      for (const edge of cfg.edges.values()) {
        if (expandedBody.has(edge.source) && !expandedBody.has(edge.target)) {
          if (canReachWithoutHeader(cfg, edge.target, header, expandedBody)) {
            expandedBody.add(edge.target);
            changed = true;
          }
        }
      }
    }

    // Find pre-header (node that has edge to header but is not in the loop)
    let preHeader: string | undefined;
    for (const edge of cfg.edges.values()) {
      if (edge.target === header && !expandedBody.has(edge.source)) {
        preHeader = edge.source;
        break;
      }
    }

    loops.push({
      header,
      body: expandedBody,
      preHeader,
      backEdges: backEdges.filter(e => e.to === header)
    });
  }

  return loops;
}

function canReachWithoutHeader(
  cfg: ControlFlowGraph, 
  nodeId: string, 
  header: string,
  loopBody: Set<string>
): boolean {
  // Simple DFS to check if node can reach header through non-header, non-loop-body nodes
  const visited = new Set<string>();
  const stack = [nodeId];

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current === header) return true;
    if (visited.has(current)) continue;
    if (loopBody.has(current)) continue;
    visited.add(current);

    for (const edge of cfg.edges.values()) {
      if (edge.source === current) {
        stack.push(edge.target);
      }
    }
  }

  return false;
}

/**
 * Compute dominance frontier
 */
export function computeDominanceFrontier(
  cfg: ControlFlowGraph,
  dominators: Map<string, DominatorNode>
): Map<string, Set<string>> {
  const frontier = new Map<string, Set<string>>();

  for (const nodeId of cfg.nodes.keys()) {
    frontier.set(nodeId, new Set());
  }

  for (const nodeId of cfg.nodes.keys()) {
    const preds = getPredecessors(cfg, nodeId);
    
    // If node has multiple predecessors or is a join point
    if (preds.length >= 2) {
      for (const pred of preds) {
        let runner = pred;
        while (runner !== dominators.get(nodeId)?.immediateDominator) {
          frontier.get(runner)?.add(nodeId);
          runner = dominators.get(runner)?.immediateDominator || runner;
          if (!runner || runner === pred) break;
        }
      }
    }
  }

  return frontier;
}

/**
 * Get CFG as adjacency list
 */
export function getCFGAdjacency(cfg: ControlFlowGraph): Map<string, Array<{ target: string; type: CFGEdgeType }>> {
  const adj = new Map<string, Array<{ target: string; type: CFGEdgeType }>>();
  
  for (const nodeId of cfg.nodes.keys()) {
    adj.set(nodeId, []);
  }

  for (const edge of cfg.edges.values()) {
    adj.get(edge.source)?.push({ target: edge.target, type: edge.type });
  }

  return adj;
}

/**
 * Find nodes reachable from entry
 */
export function getReachableNodes(cfg: ControlFlowGraph): Set<string> {
  const reachable = new Set<string>();
  const stack = [cfg.entryId];

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (reachable.has(current)) continue;
    reachable.add(current);

    for (const edge of cfg.edges.values()) {
      if (edge.source === current) {
        stack.push(edge.target);
      }
    }
  }

  return reachable;
}

/**
 * Check if CFG is reducible (simplified check)
 */
export function isReducible(cfg: ControlFlowGraph): boolean {
  const loops = detectLoops(cfg);
  
  // If all loops have single back edges, CFG is likely reducible
  for (const loop of loops) {
    if (loop.backEdges.length !== 1) {
      return false;
    }
  }
  
  return true;
}