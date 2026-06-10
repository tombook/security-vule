/**
 * Dimension #21: 博弈 (Game Theory) — Nash equilibrium proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class GameTheoryDimension extends BaseDimension {
  readonly name = 'gameTheory';
  readonly weight = 0.02;

  compute(node: CPGNode, _cpg: CPG): number {
    const exploit = node.features['exploit_value'] || 0;
    const attackCost = Math.max(1, node.features['attack_cost'] || 1);
    const defense = node.features['defense_strength'] || 0;
    const defenseCost = Math.max(1, node.features['defense_cost'] || 1);
    const attackerPayoff = exploit / attackCost;
    const defenderPayoff = defense / defenseCost;
    const total = attackerPayoff + defenderPayoff;
    return total > 0 ? attackerPayoff / total : 0.5;
  }
}