/**
 * Dimension E1: 类型论 (Type Theory)
 * Spec: §3.2
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TypeTheoryDimension extends BaseDimension {
  readonly name = 'typeTheory';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const any = node.features['any_count'] || 0;
    const untyped = node.features['untyped_count'] || 0;
    const cast = node.features['cast_count'] || 0;
    const loc = Math.max(1, node.features['loc'] || 1);
    const raw = (any * 2 + untyped + cast) / loc;
    return Math.min(1, raw);
  }
}