/**
 * Dimension #2: 开普勒轨道 (Kepler Orbit)
 * Formula: r(θ) = a(1-e²)/(1+e·cosθ)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class KeplerDimension extends BaseDimension {
  readonly name = 'kepler';
  readonly weight = 0.15;

  compute(node: CPGNode, cpg: CPG): number {
    const sinks = cpg.sinkNodes();
    if (sinks.length === 0) return 0;
    const distances: number[] = [];
    for (const sink of sinks) {
      if (sink.id === node.id) { distances.push(0); continue; }
      const path = cpg.shortestPath(node.id, sink.id);
      if (path) distances.push(path.length);
    }
    if (distances.length === 0) return 0;
    const mean = distances.reduce((s, x) => s + x, 0) / distances.length;
    const variance = distances.reduce((s, x) => s + (x - mean) ** 2, 0) / distances.length;
    const std = Math.sqrt(variance);
    const e = mean > 0 ? std / mean : 0;
    const baseRisk = mean > 0 ? 1 / (1 + mean) : 1;
    const boost = e > 1 ? (e - 1) * 0.2 : 0;
    return Math.min(1, baseRisk + boost);
  }
}