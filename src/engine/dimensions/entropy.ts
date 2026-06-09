/**
 * Dimension #10: 熵增原理 (Entropy)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class EntropyDimension extends BaseDimension {
  readonly name = 'entropy';
  readonly weight = 0.05;

  compute(node: CPGNode, _cpg: CPG): number {
    const halstead = node.features['halstead_volume'] || 0;
    const tokenDiversity = node.features['token_diversity'] || 0;
    const signal = Math.max(halstead / 1000, tokenDiversity);
    return Math.min(1, signal);
  }
}