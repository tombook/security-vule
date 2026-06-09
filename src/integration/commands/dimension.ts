/**
 * vule dimension <name> <file> — single-dimension analysis with explanation
 */
import { readFileSync } from 'fs';
import { DIMENSIONS } from '../../engine/dimensions/registry.js';

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
  const nodes = new Map<string, any>();
  lines.forEach((line, i) => {
    nodes.set(`n${i}`, {
      id: `n${i}`,
      type: 'stmt',
      file,
      line: i + 1,
      col: 0,
      code: line,
      language: 'php',
      features: {},
    });
  });
  const cpg = {
    nodes,
    edges: [],
    language: 'php',
    getNode: (id: string) => nodes.get(id),
    outEdges: () => [],
    inEdges: () => [],
    shortestPath: () => null,
    sinkNodes: () => [],
    sourcesFor: () => [],
    functions: () => [],
    callGraph: () => [],
    inDegree: () => 0,
    outDegree: () => 0,
  } as any;

  for (const node of cpg.nodes.values()) {
    const v = dim.compute(node, cpg);
    console.log(`  Node ${node.id} (line ${node.line}): ${v.toFixed(3)}`);
  }
}