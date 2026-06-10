/**
 * Dimension #20: 非平衡 (Non-Equilibrium Thermodynamics) — Onsager proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class NonEquilibriumDimension extends BaseDimension {
  readonly name = 'nonEquilibrium';
  readonly weight = 0.02;

  compute(node: CPGNode, _cpg: CPG): number {
    const commits = node.features['commit_frequency'] || 0;
    const change = node.features['change_size'] || 0;
    const refactor = node.features['refactoring'] || 0;
    const coverage = node.features['test_coverage'] || 0;
    const sigma = commits * change - refactor * coverage;
    return Math.min(1, Math.max(0, sigma / 100));
  }
}