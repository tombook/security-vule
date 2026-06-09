/**
 * Dimension #3: 轨道六要素 (Orbital Elements)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class OrbitalDimension extends BaseDimension {
  readonly name = 'orbital';
  readonly weight = 0.10;

  compute(node: CPGNode, _cpg: CPG): number {
    const pr = node.features['pagerank'] ?? 0;
    const bc = node.features['betweenness'] ?? 0;
    const ec = node.features['eigenvector'] ?? 0;
    const cc = node.features['closeness'] ?? 0;
    const centralities = [pr, bc, ec, cc];
    const nonZero = centralities.filter(x => x > 0);
    if (nonZero.length === 0) return 0;
    const mean = nonZero.reduce((s, x) => s + x, 0) / nonZero.length;
    const std = Math.sqrt(nonZero.reduce((s, x) => s + (x - mean) ** 2, 0) / nonZero.length);
    const e = mean > 0 ? std / mean : 0;
    const prRisk = Math.min(1, pr * 5);
    const eRisk = Math.min(1, e);
    return Math.min(1, (prRisk * 0.6 + eRisk * 0.4));
  }
}