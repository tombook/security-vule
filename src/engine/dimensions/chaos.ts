/**
 * Dimension #13: 混沌 (Chaos) — Lyapunov exponent proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class ChaosDimension extends BaseDimension {
  readonly name = 'chaos';
  readonly weight = 0.02;

  compute(node: CPGNode, _cpg: CPG): number {
    const depth = node.features['path_depth'] || 0;
    const branching = node.features['branching_factor'] || 0;
    return Math.min(1, (depth * branching) / 20);
  }
}