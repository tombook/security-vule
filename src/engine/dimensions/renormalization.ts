/**
 * Dimension #14: 重整化 (Renormalization) — RG flow proxy
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class RenormalizationDimension extends BaseDimension {
  readonly name = 'renormalization';
  readonly weight = 0.02;

  compute(node: CPGNode, _cpg: CPG): number {
    const instr = node.features['instruction_complexity'] || 0;
    const block = node.features['block_complexity'] || 0;
    const func = node.features['function_complexity'] || 0;
    const mod = node.features['module_complexity'] || 0;
    const total = instr + block + func + mod;
    return Math.min(1, total / 40);
  }
}