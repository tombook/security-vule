/**
 * Dimension #22: 迁移 (Transfer / Cross-File Propagation)
 * Spec: §3.1 P3
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TransferDimension extends BaseDimension {
  readonly name = 'transfer';
  readonly weight = 0.02;

  compute(node: CPGNode, cpg: CPG): number {
    const callCount = node.features['cross_file_calls'] || 0;
    const files = new Set<string>();
    for (const n of cpg.nodes.values()) files.add(n.file);
    const totalFiles = Math.max(1, files.size);
    return Math.min(1, callCount / totalFiles);
  }
}