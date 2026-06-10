/**
 * Dimension E6: 符号执行 (Symbolic Execution)
 * Spec: §3.2
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class SymbolicExecDimension extends BaseDimension {
  readonly name = 'symbolicExec';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const paths = node.features['path_count'] || 0;
    const violations = node.features['solver_violations'] || 0;
    return Math.min(1, (violations * 2 + Math.log2(Math.max(1, paths))) / 10);
  }
}