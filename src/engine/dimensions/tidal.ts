/**
 * Dimension #6: 潮汐力 (Tidal Force)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TidalDimension extends BaseDimension {
  readonly name = 'tidal';
  readonly weight = 0.10;

  compute(node: CPGNode, cpg: CPG): number {
    const sinks = cpg.sinkNodes();
    if (sinks.length < 2) return 0;
    let risk = 0;
    for (let i = 0; i < sinks.length; i++) {
      for (let j = i + 1; j < sinks.length; j++) {
        const path = cpg.shortestPath(sinks[i].id, sinks[j].id);
        if (path && path.length <= 3) {
          const d = path.length;
          const coupling = 1 / (d * d * d);
          risk += coupling;
        }
      }
    }
    return Math.min(1, risk * 0.3);
  }
}