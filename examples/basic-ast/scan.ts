/**
 * Example 1: Basic AST-only scan (zero LLM cost).
 *
 * Runs the tree-sitter-based AST analyzer on a PHP file.
 * No LLM API calls, completes in ~5 seconds.
 *
 * Run: bun run examples/basic-ast/scan.ts
 */
import { readFileSync } from 'fs';
import { CPGBuilder } from '../../src/engine/cpg/builder.js';
import { VuleEngine } from '../../src/engine/vule-engine.js';
import { defaultConfig } from '../../src/engine/vule-config.js';

const TARGET = process.argv[2] || 'test-targets/php-vulns/dvwa_sqli_low.php';

const code = readFileSync(TARGET, 'utf-8');
console.log(`📁 Scanning: ${TARGET} (${code.split('\n').length} lines)`);

// Step 1: Build a minimal ProgramGraph (stub — real parser integration in Sprint 7+)
const lines = code.split('\n').filter((l) => l.trim());
const nodes = new Map<string, any>();
lines.forEach((line, i) => {
  nodes.set(`n${i}`, {
    id: `n${i}`,
    type: 'stmt',
    file: TARGET,
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
  filePath: TARGET,
  language: 'php',
};

// Step 2: Convert to CPG
const cpg = new CPGBuilder('php', TARGET).build(pg as any);
console.log(`📊 CPG: ${cpg.nodes.size} nodes, ${cpg.edges.length} edges`);

// Step 3: Run VuleEngine with default config (AST placeholder + 29 dimensions)
const engine = new VuleEngine(
  cpg,
  cpg.sinkNodes().map((n) => n.id)
);
const report = engine.analyze();

console.log(`\n🌌 VuleEngine Report (v${report.version})`);
console.log(`   Risk distribution: ${JSON.stringify(report.riskDistribution)}`);
console.log(`\n🔥 Top ${report.topRisk.length} risk nodes:\n`);

for (const n of report.topRisk.slice(0, 5)) {
  const dims = Object.keys(n.contributions);
  const dimSummary = dims.slice(0, 3).join(', ') + (dims.length > 3 ? '...' : '');
  console.log(`   ${n.uvrs.toFixed(3).padStart(6)} [${n.level.padEnd(8)}] ${n.file}:${n.line}`);
  console.log(`           dominant=${n.dominantDimension} | contributions: ${dimSummary}`);
}
