/**
 * Dimension E5: 抽象解释 (Abstract Interpretation)
 * Spec: §3.2
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class AbstractInterpretDimension extends BaseDimension {
  readonly name = 'abstractInterpret';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const taintMax = node.features['taint_max'] || 0;
    const valueRange = node.features['value_range'] || 0;
    return Math.min(1, (taintMax + valueRange) / 10);
  }
}