/**
 * Dimension #5: 摄动理论 (Perturbation)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class PerturbationDimension extends BaseDimension {
  readonly name = 'perturbation';
  readonly weight = 0.05;

  compute(node: CPGNode, _cpg: CPG): number {
    const churn = node.features['churn'] || 0;
    const complexity = node.features['complexity'] || 0;
    const risk = (churn / 100) * (complexity / 10);
    return Math.min(1, risk);
  }
}