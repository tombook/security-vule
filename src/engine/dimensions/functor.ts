/**
 * Dimension E2: 范畴论/数据流函子 (Category Theory — Data-Flow Functor)
 * Spec: §3.2
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class FunctorDimension extends BaseDimension {
  readonly name = 'functor';
  readonly weight = 0.03;
  private verdicts: Map<string, [number, number]> = new Map();

  setVerdicts(map: Record<string, [number, number]>): void {
    this.verdicts = new Map(Object.entries(map));
  }

  compute(node: CPGNode, _cpg: CPG): number {
    const pair = this.verdicts.get(node.id);
    if (!pair) return 0;
    return Math.abs(pair[0] - pair[1]);
  }
}