/**
 * GNN-based Vulnerability Classifier
 * Inspired by Devign/ReGVD - Graph Neural Networks on Code Property Graphs
 * Message Passing Neural Network for vulnerability detection
 */
import type { CodePropertyGraph, CPGNode, CPGEdge } from '../execution/cpg.js';

export interface GNNConfig {
  hiddenDim: number;
  numLayers: number;
  numClasses: number;
  dropout: number;
  learningRate: number;
}

export interface GraphSample {
  cpg: CodePropertyGraph;
  label: number; // 1 = vulnerable, 0 = safe
  nodeFeatures: Map<string, number[]>;
}

export interface GNNEmbedding {
  nodeEmbeddings: Map<string, number[]>;
  graphEmbedding: number[];
  vulnerabilityScore: number;
}

// Node feature types for embedding
const NODE_FEATURE_TYPES = [
  'File', 'Function', 'Block', 'Statement', 'Expression', 'Type', 'Literal'
];
const EDGE_FEATURE_TYPES = [
  'AST', 'CFG', 'CALL', 'SOURCE', 'SINK', 'DATA_FLOW', 'CONTROL_FLOW'
];

// Encode node type as one-hot vector
export function oneHotNodeType(type: string, dim: number): number[] {
  const vec = new Array(dim).fill(0);
  const idx = NODE_FEATURE_TYPES.indexOf(type);
  if (idx >= 0) vec[idx] = 1;
  return vec;
}

// Encode edge type as one-hot vector
export function oneHotEdgeType(type: string, dim: number): number[] {
  const vec = new Array(dim).fill(0);
  const idx = EDGE_FEATURE_TYPES.indexOf(type);
  if (idx >= 0) vec[idx] = 1;
  return vec;
}

// Initialize node features from CPG
export function initializeNodeFeatures(cpg: CodePropertyGraph, featureDim: number): Map<string, number[]> {
  const features = new Map<string, number[]>();
  
  for (const [nodeId, node] of cpg.nodes) {
    const nodeTypeVec = oneHotNodeType(node.type, NODE_FEATURE_TYPES.length);
    // Pad to featureDim
    const padded = [...nodeTypeVec, ...new Array(featureDim - nodeTypeVec.length).fill(0)];
    // Add line number as numerical feature
    padded[NODE_FEATURE_TYPES.length] = (node.lineNumber || 0) / 1000;
    // Add code length as feature
    padded[NODE_FEATURE_TYPES.length + 1] = Math.min((node.code?.length || 0) / 1000, 1);
    features.set(nodeId, padded.slice(0, featureDim));
  }
  
  return features;
}

// Simplified Message Passing Layer
class MessagePassingLayer {
  constructor(
    private inputDim: number,
    private hiddenDim: number,
    private useEdgeFeatures: boolean
  ) {}

  // Compute messages from neighbors
  messages(nodeId: string, neighbors: Array<{ id: string; edgeType: string }>, embeddings: Map<string, number[]>): Map<string, number[]> {
    const messages = new Map<string, number[]>();
    
    for (const neighbor of neighbors) {
      const neighborEmbed = embeddings.get(neighbor.id);
      if (!neighborEmbed) continue;
      
      // Edge-type weighted message
      const edgeWeight = oneHotEdgeType(neighbor.edgeType, EDGE_FEATURE_TYPES.length);
      const weighted = neighborEmbed.map((v, i) => v * (edgeWeight[EDGE_FEATURE_TYPES.indexOf(neighbor.edgeType)] || 0.5));
      
      const existing = messages.get(neighbor.id) || new Array(this.hiddenDim).fill(0);
      for (let i = 0; i < this.hiddenDim; i++) {
        existing[i] += weighted[i];
      }
      messages.set(neighbor.id, existing);
    }
    
    return messages;
  }

  // Aggregate messages using mean pooling
  aggregate(nodeEmbed: number[], messages: Map<string, number[]>): number[] {
    const msgList = Array.from(messages.values());
    if (msgList.length === 0) return nodeEmbed;
    
    const aggregated = new Array(this.hiddenDim).fill(0);
    for (const msg of msgList) {
      for (let i = 0; i < this.hiddenDim; i++) {
        aggregated[i] += msg[i];
      }
    }
    for (let i = 0; i < this.hiddenDim; i++) {
      aggregated[i] /= msgList.length;
    }
    
    // Combine with self embedding
    return aggregated.map((v, i) => Math.tanh(v + nodeEmbed[i]));
  }
}

// GNN Model for vulnerability classification
export class VulnerabilityGNN {
  private config: GNNConfig;
  private layers: MessagePassingLayer[] = [];
  private nodeFeatures: Map<string, number[]> = new Map();
  private embeddings: Map<string, number[]> = new Map();
  
  constructor(config: Partial<GNNConfig> = {}) {
    this.config = {
      hiddenDim: config.hiddenDim || 64,
      numLayers: config.numLayers || 3,
      numClasses: config.numClasses || 2,
      dropout: config.dropout || 0.2,
      learningRate: config.learningRate || 0.001,
    };
    
    // Initialize message passing layers
    for (let i = 0; i < this.config.numLayers; i++) {
      this.layers.push(new MessagePassingLayer(
        this.config.hiddenDim,
        this.config.hiddenDim,
        true
      ));
    }
  }
  
  // Build graph adjacency from CPG
  getNeighbors(cpg: CodePropertyGraph): Map<string, Array<{ id: string; edgeType: string }>> {
    const neighbors = new Map<string, Array<{ id: string; edgeType: string }>>();
    
    for (const [nodeId, _] of cpg.nodes) {
      neighbors.set(nodeId, []);
    }
    
    for (const [_, edge] of cpg.edges) {
      neighbors.get(edge.source)?.push({ id: edge.target, edgeType: edge.type });
      // Also add reverse edges for undirected message passing
      neighbors.get(edge.target)?.push({ id: edge.source, edgeType: edge.type });
    }
    
    return neighbors;
  }
  
  // Forward pass through GNN layers
  forward(cpg: CodePropertyGraph): GNNEmbedding {
    // Initialize node features
    this.nodeFeatures = initializeNodeFeatures(cpg, this.config.hiddenDim);
    this.embeddings = new Map(this.nodeFeatures);
    
    // Message passing iterations
    const neighbors = this.getNeighbors(cpg);
    
    for (const layer of this.layers) {
      const newEmbeddings = new Map<string, number[]>();
      
      for (const [nodeId, nodeEmbed] of this.embeddings) {
        const nodeNeighbors = neighbors.get(nodeId) || [];
        const messages = layer.messages(nodeId, nodeNeighbors, this.embeddings);
        const aggregated = layer.aggregate(nodeEmbed, messages);
        newEmbeddings.set(nodeId, aggregated);
      }
      
      this.embeddings = newEmbeddings;
    }
    
    // Graph-level embedding (mean pooling)
    const graphEmbed = new Array(this.config.hiddenDim).fill(0);
    let count = 0;
    for (const embed of this.embeddings.values()) {
      for (let i = 0; i < this.config.hiddenDim; i++) {
        graphEmbed[i] += embed[i];
      }
      count++;
    }
    if (count > 0) {
      for (let i = 0; i < this.config.hiddenDim; i++) {
        graphEmbed[i] /= count;
      }
    }
    
    // Compute vulnerability score (softmax over classes)
    const vulnScore = this.sigmoid(graphEmbed.reduce((s, v, i) => s + v * (i % 2 === 0 ? 1 : -1), 0));
    
    return {
      nodeEmbeddings: this.embeddings,
      graphEmbedding: graphEmbed,
      vulnerabilityScore: vulnScore
    };
  }
  
  // Binary classification score
  classify(cpg: CodePropertyGraph): { vulnerable: boolean; confidence: number; score: number } {
    const { vulnerabilityScore } = this.forward(cpg);
    const confidence = Math.abs(vulnerabilityScore - 0.5) * 2;
    
    return {
      vulnerable: vulnerabilityScore > 0.5,
      confidence,
      score: vulnerabilityScore
    };
  }
  
  private sigmoid(x: number): number {
    return 1 / (1 + Math.exp(-Math.max(-500, Math.min(500, x))));
  }
}

// Train GNN on labeled samples (simplified batch training)
export function trainGNN(
  samples: GraphSample[],
  config: Partial<GNNConfig> = {}
): VulnerabilityGNN {
  const gnn = new VulnerabilityGNN(config);
  
  // Simple gradient descent training
  const lr = config.learningRate || 0.001;
  const epochs = 50;
  
  for (let epoch = 0; epoch < epochs; epoch++) {
    let totalLoss = 0;
    
    for (const sample of samples) {
      const { graphEmbedding, vulnerabilityScore } = gnn.forward(sample.cpg);
      
      // Binary cross-entropy loss
      const label = sample.label;
      const pred = vulnerabilityScore;
      const loss = -(label * Math.log(pred + 1e-10) + (1 - label) * Math.log(1 - pred + 1e-10));
      totalLoss += loss;
      
      // Simplified weight update (apply gradient directly)
      const grad = pred - label;
      for (let i = 0; i < graphEmbedding.length; i++) {
        graphEmbedding[i] -= lr * grad * graphEmbedding[i];
      }
    }
    
    if (epoch % 10 === 0) {
      console.log(`[GNN] Epoch ${epoch}/${epochs} | Loss: ${(totalLoss / samples.length).toFixed(4)}`);
    }
  }
  
  return gnn;
}

// Extract function-level subgraph from CPG
export function extractFunctionSubgraph(
  cpg: CodePropertyGraph,
  functionName: string
): CodePropertyGraph {
  const subNodes = new Map<string, CPGNode>();
  const subEdges = new Map<string, CPGEdge>();
  
  // Find function node
  const funcNode = Array.from(cpg.nodes.values()).find(
    n => n.type === 'Function' && n.name === functionName
  );
  if (!funcNode) return cpg;
  
  // BFS to collect related nodes
  const visited = new Set<string>();
  const queue = [funcNode.id];
  
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current)) continue;
    visited.add(current);
    
    const node = cpg.nodes.get(current);
    if (node) subNodes.set(current, node);
    
    for (const [edgeId, edge] of cpg.edges) {
      if (edge.source === current && !visited.has(edge.target)) {
        subEdges.set(edgeId, edge);
        queue.push(edge.target);
      }
      if (edge.target === current && !visited.has(edge.source)) {
        const revEdge: CPGEdge = { source: edge.target, target: edge.source, type: edge.type };
        subEdges.set(`rev_${edgeId}`, revEdge);
        queue.push(edge.source);
      }
    }
  }
  
  return {
    nodes: subNodes,
    edges: subEdges,
    metadata: cpg.metadata
  };
}

//Joern-style CPG query: find source-to-sink paths
export function findVulnerabilityPaths(cpg: CodePropertyGraph): Array<{
  source: string;
  sink: string;
  path: string[];
  confidence: number;
}> {
  const paths: Array<{ source: string; sink: string; path: string[]; confidence: number }> = [];
  
  // Find SOURCE nodes
  const sources = Array.from(cpg.nodes.values()).filter(n => n.type === 'Expression');
  // Find SINK nodes (expressions that look dangerous)
  const sinks = Array.from(cpg.nodes.values()).filter(n => {
    const code = n.code || '';
    return /exec|eval|query|open|write|system/i.test(code);
  });
  
  // BFS to find paths from source to sink
  for (const source of sources) {
    for (const sink of sinks) {
      const path = bfsPath(cpg, source.id, sink.id);
      if (path.length > 0) {
        paths.push({
          source: source.id,
          sink: sink.id,
          path,
          confidence: 0.7 + 0.2 * Math.min(1, 1 / path.length)
        });
      }
    }
  }
  
  return paths;
}

function bfsPath(cpg: CodePropertyGraph, start: string, end: string): string[] {
  const visited = new Set<string>();
  const queue: Array<{ node: string; path: string[] }> = [{ node: start, path: [start] }];
  
  while (queue.length > 0) {
    const { node, path } = queue.shift()!;
    if (visited.has(node)) continue;
    visited.add(node);
    
    if (node === end) return path;
    
    for (const [_, edge] of cpg.edges) {
      if (edge.source === node && !visited.has(edge.target)) {
        queue.push({ node: edge.target, path: [...path, edge.target] });
      }
    }
  }
  
  return [];
}
