/**
 * Dimension #19: 分形 (Fractal) — box-dimension proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class FractalDimension extends BaseDimension {
  readonly name = 'fractal';
  readonly weight = 0.02;

  compute(node: CPGNode, _cpg: CPG): number {
    const selfSim = node.features['self_similarity'] || 0;
    const optimal = 1.5;
    const deviation = Math.abs(selfSim - optimal);
    return Math.min(1, deviation);
  }
}