/**
 * Cosmic-galaxy equivalence test.
 *
 * Runs the same CPG fixture through security-vule's VuleEngine and
 * compares UVRS scores with cosmic-galaxy's output (expected-cosmic.json).
 *
 * Tolerance: 0.10 (rationale in README.md).
 */
import { describe, expect, test } from 'bun:test';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { CPGBuilder } from '../../../src/engine/cpg/builder.js';
import { createCPG } from '../../../src/engine/cpg/builder.js';
import { VuleEngine } from '../../../src/engine/vule-engine.js';
import { defaultConfig } from '../../../src/engine/vule-config.js';

const HERE = import.meta.dir;
const FIXTURE = join(HERE, 'cpg-fixture.json');
const COSMIC_OUT = join(HERE, 'expected-cosmic.json');

interface CPGFixtureNode {
  id: string;
  type: string;
  file: string;
  line: number;
  col: number;
  code: string;
  features: Record<string, number>;
}

interface CPGFixture {
  language: string;
  nodes: CPGFixtureNode[];
  edges: Array<{ source: string; target: string; kind: string }>;
}

function buildCPGFromFixture(fixture: CPGFixture) {
  const nodes = new Map<string, any>();
  for (const n of fixture.nodes) {
    nodes.set(n.id, { ...n, language: fixture.language });
  }
  return createCPG(nodes, fixture.edges as any, fixture.language as any);
}

describe('cosmic-galaxy equivalence', () => {
  test('fixture exists', () => {
    expect(existsSync(FIXTURE)).toBe(true);
  });

  test('security-vule produces valid UVRS for fixture', () => {
    const fixture: CPGFixture = JSON.parse(readFileSync(FIXTURE, 'utf-8'));
    const cpg = buildCPGFromFixture(fixture);

    const cfg = defaultConfig();
    cfg.dimensions.enabled = ['gravity', 'kepler', 'orbital', 'nbody'];
    const sinks = fixture.nodes.filter(n => n.features?.is_sink).map(n => n.id);
    const engine = new VuleEngine(cpg, sinks, [], cfg);
    const report = engine.analyze();

    const vuleScores: Record<string, number> = {};
    for (const n of report.topRisk) {
      vuleScores[n.nodeId] = n.uvrs;
    }
    // Ensure all fixture nodes have scores
    for (const n of fixture.nodes) {
      expect(vuleScores[n.id]).toBeDefined();
    }
    // All scores in [0, 1)
    for (const v of Object.values(vuleScores)) {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1.0);
    }
  });

  test('vule engine returns consistent scores on repeat calls', () => {
    const fixture: CPGFixture = JSON.parse(readFileSync(FIXTURE, 'utf-8'));
    const cpg = buildCPGFromFixture(fixture);
    const cfg = defaultConfig();
    cfg.dimensions.enabled = ['gravity', 'kepler'];
    const sinks = fixture.nodes.filter(n => n.features?.is_sink).map(n => n.id);
    const engine = new VuleEngine(cpg, sinks, [], cfg);
    const r1 = engine.analyze();
    const r2 = engine.analyze();
    expect(r1.topRisk.length).toBe(r2.topRisk.length);
    for (let i = 0; i < r1.topRisk.length; i++) {
      expect(r1.topRisk[i].uvrs).toBeCloseTo(r2.topRisk[i].uvrs, 5);
    }
  });

  test('security-vule UVRS matches cosmic-galaxy within tolerance (when cosmic output present)', () => {
    if (!existsSync(COSMIC_OUT)) {
      console.warn(`Skipping: ${COSMIC_OUT} not found. Run run_cosmic.py first.`);
      return;
    }
    const fixture: CPGFixture = JSON.parse(readFileSync(FIXTURE, 'utf-8'));
    const cosmic = JSON.parse(readFileSync(COSMIC_OUT, 'utf-8'));
    const tolerance = 0.10;

    // Run security-vule
    const cpg = buildCPGFromFixture(fixture);
    const cfg = defaultConfig();
    cfg.dimensions.enabled = ['gravity', 'kepler', 'tidal', 'relativistic', 'entropy', 'orbital'];
    const sinks = fixture.nodes.filter(n => n.features?.is_sink).map(n => n.id);
    const engine = new VuleEngine(cpg, sinks, [], cfg);
    const report = engine.analyze();
    const vuleScores: Record<string, number> = {};
    for (const n of report.topRisk) vuleScores[n.nodeId] = n.uvrs;

    // Compare
    for (const [nodeId, cosmicScore] of Object.entries(cosmic.scores)) {
      const vuleScore = vuleScores[nodeId];
      if (vuleScore === undefined) {
        console.warn(`Node ${nodeId} missing in vule output`);
        continue;
      }
      const delta = Math.abs(vuleScore - (cosmicScore as number));
      expect(delta).toBeLessThanOrEqual(tolerance);
    }
  });
});