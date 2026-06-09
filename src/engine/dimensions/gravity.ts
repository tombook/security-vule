/**
 * Dimension #1: 引力场 (Gravity Field)
 * Formula: F_ij = Γ · (W_src · W_sink) / d_ij²
 * Spec: §3.1, theory/dimensions/gravity.md
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

const GAMMA = 0.20;

export class GravityDimension extends BaseDimension {
  readonly name = 'gravity';
  readonly weight = 0.20;

  compute(node: CPGNode, cpg: CPG): number {
    const sinks = cpg.sinkNodes();
    if (sinks.length === 0) return 0;
    let maxRisk = 0;
    for (const sink of sinks) {
      if (sink.id === node.id) {
        const sources = cpg.sourcesFor(sink.id);
        for (const src of sources) {
          const wSrc = (src.features['sensitivity'] || 0.5);
          const wSink = (sink.features['dangerousness'] || 0.7);
          const path = cpg.shortestPath(src.id, sink.id);
          const d = Math.max(1, path?.length || 1);
          const risk = GAMMA * (wSrc * wSink) / (d * d);
          maxRisk = Math.max(maxRisk, risk);
        }
      } else {
        const path = cpg.shortestPath(node.id, sink.id);
        if (!path) continue;
        const wSrc = (node.features['sensitivity'] || 0.5);
        const wSink = (sink.features['dangerousness'] || 0.7);
        const d = path.length;
        const risk = GAMMA * (wSrc * wSink) / (d * d);
        maxRisk = Math.max(maxRisk, risk);
      }
    }
    return Math.min(1, maxRisk);
  }
}