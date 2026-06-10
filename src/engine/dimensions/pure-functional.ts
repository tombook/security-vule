/**
 * Dimension E4: 纯函数式 (Pure Functional Security)
 * Spec: §3.2
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class PureFunctionalDimension extends BaseDimension {
  readonly name = 'pureFunctional';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const mut = node.features['mutable_vars'] || 0;
    const effects = node.features['side_effects'] || 0;
    const total = Math.max(1, node.features['loc'] || 1);
    return Math.min(1, (mut * 0.5 + effects) / total);
  }
}