/**
 * Dimension #11/23: 微分几何 (Differential Geometry) — Ricci curvature proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class DifferentialGeometryDimension extends BaseDimension {
  readonly name = 'differentialGeometry';
  readonly weight = 0.02;

  compute(node: CPGNode, cpg: CPG): number {
    const neighborComplexities: number[] = [];
    for (const e of cpg.outEdges(node.id)) {
      const n = cpg.getNode(e.target);
      if (n?.features['complexity']) neighborComplexities.push(n.features['complexity']);
    }
    for (const e of cpg.inEdges(node.id)) {
      const n = cpg.getNode(e.source);
      if (n?.features['complexity']) neighborComplexities.push(n.features['complexity']);
    }
    if (neighborComplexities.length === 0) return 0;
    const mean = neighborComplexities.reduce((s, x) => s + x, 0) / neighborComplexities.length;
    const variance = neighborComplexities.reduce((s, x) => s + (x - mean) ** 2, 0) / neighborComplexities.length;
    return Math.min(1, Math.sqrt(variance) / 10);
  }
}