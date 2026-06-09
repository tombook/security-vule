/**
 * Dimension #7: 相对论修正 (Relativistic Correction)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class RelativisticDimension extends BaseDimension {
  readonly name = 'relativistic';
  readonly weight = 0.10;

  compute(node: CPGNode, _cpg: CPG): number {
    const depth = node.features['nesting_depth'] || 0;
    const cyclo = node.features['cyclomatic_complexity'] || 0;
    const curvatureRisk = depth > 5 ? 1 - 1 / (depth - 4) : 0;
    const complexityRisk = Math.min(1, cyclo / 20);
    return Math.min(1, Math.max(curvatureRisk, complexityRisk));
  }
}