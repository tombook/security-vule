/**
 * Example 3: Build a CPG from a file.
 *
 * Demonstrates how to construct a Code Property Graph programmatically
 * and query it via the CPG API.
 *
 * Run: bun run examples/cpg-construction/build.ts
 */
import { readFileSync } from 'fs';
import { CPGBuilder, createCPG } from '../../src/engine/cpg/builder.js';
import { bfs, dfs, downstreamNodes, upstreamNodes } from '../../src/engine/cpg/queries.js';
import {
  computePagerank,
  computeBetweenness,
  computeDegreeStats,
} from '../../src/engine/cpg/metrics.js';
import { isSinkFunction } from '../../src/engine/cpg/sinks.js';
import { childLogger } from '../../src/utils/logger.js';

const log = childLogger('examples.cpg');

const TARGET = process.argv[2] || 'test-targets/php-vulns/dvwa_sqli_low.php';
const code = readFileSync(TARGET, 'utf-8');
log.info({ target: TARGET }, 'building CPG');

// Step 1: Build minimal PG
const lines = code.split('\n').filter((l) => l.trim());
const nodes = new Map<string, any>();
lines.forEach((line, i) => {
  nodes.set(`n${i}`, {
    id: `n${i}`,
    type: line.includes('$_GET') || line.includes('$_POST') ? 'var' : 'stmt',
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

// Step 3: Query the CPG
console.log(`\n📊 CPG Stats:`);
console.log(`   Nodes: ${cpg.nodes.size}, Edges: ${cpg.edges.length}`);

const stats = computeDegreeStats(cpg);
console.log(
  `   Avg degree: ${stats.avgDegree.toFixed(2)}, Max in: ${stats.maxInDegree}, Max out: ${stats.maxOutDegree}`
);

const sinks = cpg.sinkNodes();
console.log(`   Sink functions detected: ${sinks.length}`);
for (const s of sinks) {
  console.log(`      → ${s.code.slice(0, 60)}`);
}

// Step 4: Identify dangerous PHP functions via sink detection
console.log(`\n🎯 Dangerous functions in file (via isSinkFunction):`);
for (const line of code.split('\n')) {
  const m = line.match(/(\w+)\s*\(/);
  if (m && isSinkFunction(m[1], 'php')) {
    console.log(`   ${m[1]}() → sink (dangerous)`);
  }
}

// Step 5: PageRank
const pr = computePagerank(cpg, 20);
const topPR = Array.from(pr.entries())
  .sort((a, b) => b[1] - a[1])
  .slice(0, 3);
console.log(`\n📈 Top-3 PageRank nodes:`);
for (const [id, score] of topPR) {
  const node = cpg.getNode(id);
  console.log(`   ${score.toFixed(4)} ${id} → ${node?.code.slice(0, 50)}`);
}

// Step 6: Betweenness
const bc = computeBetweenness(cpg);
const topBC = Array.from(bc.entries())
  .sort((a, b) => b[1] - a[1])
  .slice(0, 3);
console.log(`\n🌉 Top-3 Betweenness nodes:`);
for (const [id, score] of topBC) {
  console.log(`   ${score.toFixed(4)} ${id}`);
}
