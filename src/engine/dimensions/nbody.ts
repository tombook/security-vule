/**
 * Dimension #4: N体 (Multi-LLM Consensus)
 * Spec: §3.1; uses src/llm/consensus.ts
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class NBodyDimension extends BaseDimension {
  readonly name = 'nbody';
  readonly weight = 0.10;
  private consensusMap: Map<string, number> = new Map();

  setConsensusContext(map: Record<string, number>): void {
    this.consensusMap = new Map(Object.entries(map));
  }

  compute(node: CPGNode, _cpg: CPG): number {
    const agreement = this.consensusMap.get(node.id);
    if (agreement === undefined) return 0;
    return Math.max(0, Math.min(1, agreement));
  }
}