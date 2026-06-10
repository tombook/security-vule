/**
 * Example 5: Add a custom dimension detector.
 *
 * Demonstrates how to extend the cosmic-galaxy-aligned dimension
 * registry with your own detectors.
 *
 * Run: bun run examples/custom-dimension/example.ts
 */
import { CPGBuilder } from '../../src/engine/cpg/builder.js';
import { VuleEngine } from '../../src/engine/vule-engine.js';
import { BaseDimension } from '../../src/engine/dimensions/base.js';
import type { CPG, CPGNode } from '../../src/engine/cpg/types.js';

/**
 * Custom dimension: detect functions with too many parameters (>5).
 * In cosmic-galaxy terms, this is a "complexity entropy" dimension.
 */
class TooManyParametersDimension extends BaseDimension {
  readonly name = 'tooManyParams';
  readonly weight = 0.02;

  compute(node: CPGNode, _cpg: CPG): number {
    const code = node.code || '';
    // Match function definitions: function foo(a, b, c, ...)
    const m = code.match(/function\s+\w+\s*\(([^)]*)\)/);
    if (!m) return 0;
    const params = m[1]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    // Risk scales with number of params above 3
    if (params.length <= 3) return 0;
    return Math.min(1, (params.length - 3) / 5);
  }
}

// Step 1: Build CPG from a sample
const code = `
<?php
function simple() { return 1; }
function okParams($a, $b, $c) { return $a + $b + $c; }
function manyParams($a, $b, $c, $d, $e, $f, $g) { return $a; }
?>
`;
const lines = code.split('\n').filter((l) => l.trim());
const nodes = new Map<string, any>();
lines.forEach((line, i) => {
  nodes.set(`n${i}`, {
    id: `n${i}`,
    type: 'stmt',
    file: 'sample.php',
    line: i + 1,
    col: 0,
    code: line,
    language: 'php',
    properties: new Map(),
  });
});
const edges: any[] = [];
for (let i = 0; i < lines.length - 1; i++) {
  edges.push({ source: `n${i}`, target: `n${i + 1}`, type: 'DFG' });
}
const pg = {
  nodes,
  edges,
  nodeCount: lines.length,
  edgeCount: edges.length,
  edgeTypeCounts: {} as any,
  filePath: 'sample.php',
  language: 'php',
};
const cpg = new CPGBuilder('php', 'sample.php').build(pg as any);

// Step 2: Register the custom dimension
import { registerDimension, DIMENSIONS } from '../../src/engine/dimensions/registry.js';
registerDimension(new TooManyParametersDimension());
console.log(`✅ Registered custom dimension: tooManyParams (weight=0.02)`);
console.log(`   Total dimensions: ${Object.keys(DIMENSIONS).length}`);

// Step 3: Run VuleEngine with custom dimension enabled
const engine = new VuleEngine(
  cpg,
  cpg.sinkNodes().map((n) => n.id)
);
engine.config.dimensions.enabled = ['tooManyParams'];
const report = engine.analyze();

console.log(`\n📊 Results for custom dimension:\n`);
for (const n of report.topRisk) {
  const risk = n.contributions['tooManyParams'] || 0;
  if (risk > 0) {
    console.log(`   ${n.file}:${n.line} → risk=${risk.toFixed(2)} | ${n.code.slice(0, 50)}`);
  }
}
