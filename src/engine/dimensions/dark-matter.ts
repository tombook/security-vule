/**
 * Dimension #8: 暗物质/暗能量 (Dark Matter)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

const DARK_PATTERNS = ['reflection', 'eval', 'include', 'require', 'dl', 'ffi', 'callback', 'listener'];

export class DarkMatterDimension extends BaseDimension {
  readonly name = 'darkMatter';
  readonly weight = 0.08;

  compute(node: CPGNode, _cpg: CPG): number {
    let count = node.features['dynamic_calls'] || 0;
    for (const p of DARK_PATTERNS) {
      if (node.features[p]) count += node.features[p];
    }
    return Math.min(1, count / 5);
  }
}