/**
 * Dimension E3: 拓扑数据分析 (Topological Data Analysis)
 * Spec: §3.2
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TdaDimension extends BaseDimension {
  readonly name = 'tda';
  readonly weight = 0.03;

  compute(node: CPGNode, cpg: CPG): number {
    const visited = new Set<string>();
    const queue = [node.id];
    while (queue.length) {
      const cur = queue.shift()!;
      if (visited.has(cur)) continue;
      visited.add(cur);
      for (const e of cpg.outEdges(cur)) queue.push(e.target);
      for (const e of cpg.inEdges(cur)) queue.push(e.source);
    }
    const beta0 = visited.size > 0 ? 1 : 0;
    const totalNodes = cpg.nodes.size;
    const totalEdges = cpg.edges.length;
    // Euler characteristic: V - E + F = 1 + β₀ - β₁ (for connected planar graph)
    // Approximation: β₁ ≈ edges - nodes + components
    const beta1 = Math.max(0, totalEdges - totalNodes + beta0);
    return Math.min(1, beta1 / 5);
  }
}