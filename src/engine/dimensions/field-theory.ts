/**
 * Dimension #16: 场论 (Field Theory) — Lagrangian proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class FieldTheoryDimension extends BaseDimension {
  readonly name = 'fieldTheory';
  readonly weight = 0.02;

  compute(node: CPGNode, _cpg: CPG): number {
    const T = node.features['assignments'] || 0;
    const V = (node.features['cyclomatic_complexity'] || 0) + (node.features['nesting_depth'] || 0);
    const imbalance = Math.abs(T - V);
    return Math.min(1, imbalance / 20);
  }
}