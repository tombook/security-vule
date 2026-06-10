/**
 * vule dimension <name> <file> — single-dimension analysis with explanation
 */
import { readFileSync } from 'fs';
import { DIMENSIONS } from '../../engine/dimensions/registry.js';
import { createCPG } from '../../engine/cpg/builder.js';
import type { CPG, CPGNode } from '../../engine/cpg/types.js';

export async function dimensionCommand(name: string, file: string): Promise<void> {
  const dim = DIMENSIONS[name];
  if (!dim) {
    console.error(`Unknown dimension: ${name}. Available: ${Object.keys(DIMENSIONS).join(', ')}`);
    process.exit(1);
  }
  const code = readFileSync(file, 'utf-8');
  console.log(`\n🔬 Dimension: ${name} (weight: ${dim.weight})`);
  console.log(`📁 File: ${file} (${code.split('\n').length} lines)`);

  // Mock CPG: 1 node per line
  const lines = code.split('\n');
  const nodeMap = new Map<string, CPGNode>();
  lines.forEach((line, i) => {
    const id = `n${i}`;
    nodeMap.set(id, {
      id,
      type: 'stmt',
      file,
      line: i + 1,
      col: 0,
      code: line,
      language: 'php',
      features: {},
    });
  });
  const cpg = createCPG(nodeMap, [], 'php') as CPG;

  for (const node of cpg.nodes.values()) {
    const v = dim.compute(node, cpg);
    console.log(`  Node ${node.id} (line ${node.line}): ${v.toFixed(3)}`);
  }
}
