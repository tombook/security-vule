/**
 * BaseDimension — abstract base for all cosmic-galaxy dimension detectors.
 * Spec: §4.2 Dimension Registry
 */
import type { CPG, CPGNode } from '../cpg/types.js';

export interface DimensionModule {
  readonly name: string;
  readonly weight: number;
  compute(node: CPGNode, cpg: CPG): number;
  explain?(node: CPGNode, cpg: CPG): string;
  llmPrompt?(node: CPGNode, cpg: CPG): string;
}

export abstract class BaseDimension implements DimensionModule {
  abstract readonly name: string;
  abstract readonly weight: number;
  abstract compute(node: CPGNode, cpg: CPG): number;
}