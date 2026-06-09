/**
 * Dimension #17: 信息论 (Information Theory)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

const OPTIMAL = 4.5;
const RANGE = 1.0;

export class InformationDimension extends BaseDimension {
  readonly name = 'information';
  readonly weight = 0.04;

  compute(node: CPGNode, _cpg: CPG): number {
    const h = node.features['token_entropy'];
    if (h === undefined) return 0;
    const deviation = Math.abs(h - OPTIMAL) / RANGE;
    return Math.min(1, deviation);
  }
}