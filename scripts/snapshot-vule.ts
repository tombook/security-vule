/**
 * snapshot-vule.ts — Generate expected-vule.json snapshot from cpg-fixture.json
 *
 * Usage: bun --bun scripts/snapshot-vule.ts
 */
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { createCPG } from '../src/engine/cpg/builder.js';
import { VuleEngine } from '../src/engine/vule-engine.js';
import { defaultConfig } from '../src/engine/vule-config.js';

const FIXTURE = join(import.meta.dir, '../tests/integration/cosmic-galaxy/cpg-fixture.json');
const OUTPUT = join(import.meta.dir, '../tests/integration/cosmic-galaxy/expected-vule.json');

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

const fixture: CPGFixture = JSON.parse(readFileSync(FIXTURE, 'utf-8'));

const nodes = new Map<string, any>();
for (const n of fixture.nodes) {
  nodes.set(n.id, { ...n, language: fixture.language });
}
const cpg = createCPG(nodes, fixture.edges as any, fixture.language as any);

const cfg = defaultConfig();
cfg.dimensions.enabled = ['gravity', 'kepler', 'tidal', 'relativistic', 'entropy', 'orbital'];
const sinks = fixture.nodes.filter(n => n.features?.is_sink).map(n => n.id);
const engine = new VuleEngine(cpg, sinks, [], cfg);
const report = engine.analyze();
const scores: Record<string, number> = {};
for (const n of report.topRisk) scores[n.nodeId] = n.uvrs;

const result = {
  tool: 'security-vule',
  version: '0.3.0',
  scores,
  tolerance: 0.10,
};

writeFileSync(OUTPUT, JSON.stringify(result, null, 2));
console.log(`Wrote ${OUTPUT}`);
for (const [k, v] of Object.entries(scores)) console.log(`  ${k}: ${v.toFixed(3)}`);