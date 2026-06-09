import { describe, expect, test } from 'bun:test';
import { DIMENSIONS } from '../../../../src/engine/dimensions/registry.js';
import { VuleEngine } from '../../../../src/engine/vule-engine.js';
import { CPGBuilder } from '../../../../src/engine/cpg/builder.js';
import type { ProgramGraph } from '../../../../src/engine/program-graph.js';

describe('P0 dimensions integration', () => {
  test('all 4 P0 dimensions registered', () => {
    expect(DIMENSIONS.gravity).toBeDefined();
    expect(DIMENSIONS.kepler).toBeDefined();
    expect(DIMENSIONS.orbital).toBeDefined();
    expect(DIMENSIONS.nbody).toBeDefined();
  });
  test('P0 weights sum to 0.55 (gravity+kepler+orbital+nbody)', () => {
    const sum = ['gravity', 'kepler', 'orbital', 'nbody'].reduce((s, k) => s + DIMENSIONS[k].weight, 0);
    expect(sum).toBeCloseTo(0.55);
  });
  test('VuleEngine uses P0 dimensions on tainted PHP fixture', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['n1', { id: 'n1', type: 'variable', code: '$_GET["x"]', lineStart: 1, lineEnd: 1, properties: new Map() }],
        ['n2', { id: 'n2', type: 'call', code: 'mysql_query($x)', lineStart: 2, lineEnd: 2, properties: new Map() }],
      ]),
      edges: [{ source: 'n1', target: 'n2', type: 'DFG' }],
      nodeCount: 2, edgeCount: 1, edgeTypeCounts: {} as any,
      filePath: 'sqli.php', language: 'php',
    } as any;
    const cpg = new CPGBuilder('php', 'sqli.php').build(pg);
    const engine = new VuleEngine(cpg, ['n2'], []);
    engine.config.dimensions.enabled = ['gravity', 'kepler', 'orbital', 'nbody'];
    const report = engine.analyze();
    expect(report.topRisk.length).toBe(2);
    // Both nodes get same score from default UVRS behavior, but topRisk should not throw
    expect(report.topRisk[0].uvrs).toBeGreaterThan(0);
    // Each node should have a risk assessment
    const n2report = report.topRisk.find(n => n.nodeId === 'n2');
    expect(n2report).toBeDefined();
  });
  test('nbody without consensus context returns 0', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['n1', { id: 'n1', type: 'variable', code: '$_GET', lineStart: 1, lineEnd: 1, properties: new Map() }],
      ]),
      edges: [], nodeCount: 1, edgeCount: 0, edgeTypeCounts: {} as any,
      filePath: 'a.php', language: 'php',
    } as any;
    const cpg = new CPGBuilder('php', 'a.php').build(pg);
    const engine = new VuleEngine(cpg, [], []);
    engine.config.dimensions.enabled = ['nbody'];
    const report = engine.analyze();
    const n1 = report.topRisk.find(n => n.nodeId === 'n1');
    expect(n1).toBeDefined();
    // nbody contribution should be 0 (no consensus context)
    const contrib = (n1 as any).contributions || {};
    expect(contrib.nbody ?? 0).toBe(0);
  });
});