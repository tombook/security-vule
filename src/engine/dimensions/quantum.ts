/**
 * Dimension #9: 量子态 (Quantum State)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class QuantumDimension extends BaseDimension {
  readonly name = 'quantum';
  readonly weight = 0.07;

  compute(node: CPGNode, _cpg: CPG): number {
    const concurrency = (node.features['shared_state'] || 0) +
      (node.features['async_await'] || 0) +
      (node.features['threads'] || 0);
    return Math.min(1, concurrency / 5);
  }
}