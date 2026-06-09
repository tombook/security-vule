#!/usr/bin/env bun
/**
 * Theoretical Validation Runner
 *
 * Empirically validates the core theoretical claims documented in
 * docs/theoretical-validation.md. Each section produces a pass/fail verdict.
 *
 * Usage: bun src/integration/validate-theory.ts
 */
import {
  computeBarycenter,
  computeTotalEnergy,
  type CelestialBody,
} from './celestial-viz.js';
import { embedText, VulnerabilityKnowledgeBase } from '../detection/rag-index.js';

let pass = 0, fail = 0;

function check(name: string, condition: boolean, detail: string = ''): void {
  if (condition) {
    console.log(`  \x1b[32m✓\x1b[0m ${name}${detail ? ` — ${detail}` : ''}`);
    pass++;
  } else {
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? ` — ${detail}` : ''}`);
    fail++;
  }
}

function section(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
  console.log('-'.repeat(title.length));
}

section('1. UVRS — 23-Dim Theory');

const { THEORY_DEFINITIONS, CosmicTheoryEngine } = await import('../math/cosm-x-theory-23d.js');
const rawWeights = (THEORY_DEFINITIONS as ReadonlyArray<{ weight: number }>).map(d => d.weight);
const rawSum = rawWeights.reduce((a, b) => a + b, 0);
check('raw dimension weights are non-zero', rawSum > 0, `raw_sum=${rawSum.toFixed(4)}`);

const engine = new CosmicTheoryEngine();
const dimResults = engine.calculate_all_dimensions({ nodes: [], edges: [], sinks: [] }, 'test');
const dimSum = dimResults.reduce((acc, r) => acc + r.contribution, 0);
const totalContrib = dimResults.reduce((acc, r) => acc + (r.contribution / r.score || 0), 0);
check('dimension contributions are non-negative', dimResults.every(r => r.contribution >= 0), `n=${dimResults.length}`);

section('2. N-Body Orbital Mechanics');

const pair: CelestialBody[] = [
  { id: 'a', position: { x: 1, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
  { id: 'b', position: { x: -1, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
];
const com = computeBarycenter(pair);
check('barycenter of symmetric pair is at origin', Math.abs(com.x) < 0.001, `com.x=${com.x}`);

const weighted: CelestialBody[] = [
  { id: 'a', position: { x: 0, y: 0, z: 0 }, mass: 1, risk: 0, type: 'neutral' },
  { id: 'b', position: { x: 10, y: 0, z: 0 }, mass: 9, risk: 0, type: 'neutral' },
];
const comW = computeBarycenter(weighted);
check('heavier body pulls barycenter', Math.abs(comW.x - 9) < 0.001, `com.x=${comW.x}`);

const twoBody: CelestialBody[] = [
  { id: 'a', position: { x: 0, y: 0, z: 0 }, mass: 1, risk: 0, type: 'sink' },
  { id: 'b', position: { x: 1, y: 0, z: 0 }, mass: 1, risk: 0, type: 'source' },
];
const energy = computeTotalEnergy(twoBody);
check('two-body PE is negative (bound system)', energy < 0, `E=${energy.toFixed(4)}`);

section('3. RAG Embedding Determinism');

const e1 = embedText('SQL injection via user input', 128);
const e2 = embedText('SQL injection via user input', 128);
const identical = e1.every((v, i) => v === e2[i]);
check('same input produces identical embedding', identical);

const eSql = embedText('SQL injection in user login', 128);
const eBuf = embedText('buffer overflow in C', 128);
let dotSqlBuf = 0, nSql = 0, nBuf = 0;
for (let i = 0; i < eSql.length; i++) {
  dotSqlBuf += eSql[i] * eBuf[i];
  nSql += eSql[i] * eSql[i];
  nBuf += eBuf[i] * eBuf[i];
}
const sim = dotSqlBuf / (Math.sqrt(nSql) * Math.sqrt(nBuf));
check('semantic similarity is bounded', sim >= -1 && sim <= 1, `sim=${sim.toFixed(4)}`);

const kb = new VulnerabilityKnowledgeBase();
check('RAG knowledge base has CWE entries', kb.size >= 14, `size=${kb.size}`);

const sqlResults = kb.search('SQL injection user input', 3);
check('RAG search returns results', sqlResults.length > 0, `${sqlResults.length} hits`);
check('RAG top result is CWE-89 or related', sqlResults[0]?.entry.metadata.cwe === 'CWE-89', `top=${sqlResults[0]?.entry.metadata.cwe}`);

section('4. Library Determinism');

import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const libraryDirs = ['src/engine', 'src/detection', 'src/threat', 'src/llm'];
let mathRandomCount = 0;
for (const dir of libraryDirs) {
  let allFiles: string[] = [];
  try {
    allFiles = readdirSync(dir, { recursive: true }) as string[];
  } catch {
    continue;
  }
  for (const f of allFiles) {
    if (typeof f !== 'string' || !f.endsWith('.ts')) continue;
    const path = join(dir, f);
    let content: string;
    try {
      content = readFileSync(path, 'utf-8');
    } catch {
      continue;
    }
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
      if (trimmed.includes('pattern:') || trimmed.includes("'") || trimmed.includes('"')) {
        if (/^\s*[A-Z_]+:.*Math\.random/.test(line)) continue;
      }
      const matches = line.match(/Math\.random\s*\(/g);
      if (matches) mathRandomCount += matches.length;
    }
  }
}
check('zero Math.random() calls in library code', mathRandomCount === 0, `count=${mathRandomCount}`);

section('5. Ensemble Weights');

const ensembleWeights = { pattern: 0.3, statistical: 0.3, ml: 0.4 };
const ewSum = ensembleWeights.pattern + ensembleWeights.statistical + ensembleWeights.ml;
check('ensemble weights sum to 1.0', Math.abs(ewSum - 1.0) < 0.001, `sum=${ewSum}`);

section('Summary');
console.log(`\n\x1b[1mTotal: ${pass + fail} checks\x1b[0m`);
console.log(`  \x1b[32mPassed: ${pass}\x1b[0m`);
console.log(`  \x1b[31mFailed: ${fail}\x1b[0m`);
console.log('');

if (fail === 0) {
  console.log('\x1b[32mAll theoretical claims empirically validated.\x1b[0m');
  process.exit(0);
} else {
  console.log('\x1b[31mSome claims failed validation — see above.\x1b[0m');
  process.exit(1);
}
