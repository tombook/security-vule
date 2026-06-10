import { describe, expect, test } from 'bun:test';
import { CPGBuilder } from '../../src/engine/cpg/builder.js';
import { VuleEngine } from '../../src/engine/vule-engine.js';
import { defaultConfig } from '../../src/engine/vule-config.js';

function generateLargePG(nodeCount: number): any {
  const nodes = new Map();
  const edges: any[] = [];
  for (let i = 0; i < nodeCount; i++) {
    nodes.set(`n${i}`, {
      id: `n${i}`,
      type: 'stmt',
      code: `$x${i}`,
      lineStart: i + 1,
      lineEnd: i + 1,
      properties: new Map(i % 50 === 0 ? [['is_sink', 1], ['dangerousness', 0.9]] : []),
    });
    if (i > 0) edges.push({ source: `n${i - 1}`, target: `n${i}`, type: 'DFG' });
  }
  return { nodes, edges, nodeCount, edgeCount: nodeCount - 1, edgeTypeCounts: {}, filePath: 'perf.php', language: 'php' };
}

describe('Performance', () => {
  test('analyzes 100-node CPG in < 1s', () => {
    const pg = generateLargePG(100);
    const cpg = new CPGBuilder('php', 'perf.php').build(pg as any);
    const sinks = cpg.sinkNodes().map(n => n.id);
    const engine = new VuleEngine(cpg, sinks, []);
    const t0 = performance.now();
    engine.analyze();
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeLessThan(1000);
  });
  test('analyzes 500-node CPG in < 5s', () => {
    const pg = generateLargePG(500);
    const cpg = new CPGBuilder('php', 'perf.php').build(pg as any);
    const sinks = cpg.sinkNodes().map(n => n.id);
    const engine = new VuleEngine(cpg, sinks, []);
    const t0 = performance.now();
    engine.analyze();
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeLessThan(5000);
  });
});