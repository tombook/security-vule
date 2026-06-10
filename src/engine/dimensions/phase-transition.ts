/**
 * Dimension #15: 相变 (Phase Transition) — Ising model proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class PhaseTransitionDimension extends BaseDimension {
  readonly name = 'phaseTransition';
  readonly weight = 0.02;

  compute(node: CPGNode, cpg: CPG): number {
    const J = node.features['coupling'] || 0;
    const h = node.features['audit_pressure'] || 0;
    const neighbors = cpg.outDegree(node.id) + cpg.inDegree(node.id);
    const totalSpinAlignment = neighbors * J;
    return Math.min(1, Math.exp(-(totalSpinAlignment + h) / 10));
  }
}