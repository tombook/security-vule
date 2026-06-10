/**
 * Dimension #18: 范畴论基础 (Category Theory - Basic) — morphism density
 * Spec: §3.1 P3 (distinct from Sprint 6's functor dimension)
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class CategoryBasicDimension extends BaseDimension {
  readonly name = 'categoryBasic';
  readonly weight = 0.02;

  compute(_node: CPGNode, cpg: CPG): number {
    const totalEdges = cpg.edges.length;
    const totalNodes = Math.max(1, cpg.nodes.size);
    const density = totalEdges / totalNodes;
    return Math.min(1, density / 5);
  }
}