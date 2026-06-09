/**
 * Dimension #12: 拓扑 (Topology)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TopologyDimension extends BaseDimension {
  readonly name = 'topology';
  readonly weight = 0.05;

  compute(node: CPGNode, cpg: CPG): number {
    let cycles = 0;
    const visited = new Set<string>();
    const stack: Array<{ node: string; ancestors: Set<string> }> = [
      { node: node.id, ancestors: new Set() },
    ];
    while (stack.length) {
      const { node: cur, ancestors } = stack.pop()!;
      if (visited.has(cur)) { cycles++; continue; }
      visited.add(cur);
      const newAncestors = new Set([...ancestors, cur]);
      for (const e of cpg.outEdges(cur)) {
        if (newAncestors.has(e.target)) cycles++;
        else stack.push({ node: e.target, ancestors: newAncestors });
      }
    }
    return Math.min(1, cycles / 3);
  }
}