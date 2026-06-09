# Sprint 2: VuleEngine + UVRS Deep Integration Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `VuleEngine` — the unified entry point that wraps CPG + dimensions registry + UVRS scoring — and integrate it with the existing `LLMAgent`/`Consensus`/UVRS modules. The engine becomes the public API surface for downstream Sprints.

**Architecture:** `VuleEngine` accepts a `CPG`, `sinks`, `securityAPIs`, optional `VuleConfig`. It lazily instantiates dimension detectors from a `DimensionRegistry`, computes per-node UVRS, and exposes `analyze()`/`topRiskNodes()`/`exportReport()`/`visualize()`. Backed by the existing `src/engine/uvrs.ts` (UVRS core) and `src/detection/llm-agent.ts` (LLM-backed analysis).

**Tech Stack:** TypeScript, Bun, YAML config via `js-yaml`.

**Spec reference:** §4 (VuleEngine).

**Depends on:** Sprint 1 (CPG core).

---

## File Structure

| File | Responsibility | Lines |
|------|---------------|-------|
| `src/engine/dimensions/registry.ts` | DimensionModule interface + DIMENSIONS registry | ~60 |
| `src/engine/dimensions/base.ts` | BaseDimension class with shared helpers | ~80 |
| `src/engine/dimensions/ast-placeholder.ts` | Placeholder for sprint 3 dimension | ~30 |
| `src/engine/vule-config.ts` | VuleConfig type + YAML loader | ~80 |
| `src/engine/vule-engine.ts` | VuleEngine class (main entry) | ~250 |
| `src/engine/vule-report.ts` | VuleReport + exportReport (JSON/HTML/MD) | ~150 |
| `config/vule.yaml` | Default config | ~80 |
| `tests/unit/engine/vule-config.test.ts` | Config loader tests | ~80 |
| `tests/unit/engine/vule-engine.test.ts` | Engine tests (mock CPG) | ~200 |
| `tests/unit/engine/dimensions/registry.test.ts` | Registry tests | ~60 |

**Total**: ~11 files, ~1080 lines.

---

## Task 1: DimensionModule Interface

**Files:**
- Create: `src/engine/dimensions/base.ts`
- Test: `tests/unit/engine/dimensions/registry.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/unit/engine/dimensions/registry.test.ts
import { describe, expect, test } from 'bun:test';
import { BaseDimension } from '../../../../src/engine/dimensions/base.js';
import type { CPG } from '../../../../src/engine/cpg/types.js';

class TestDim extends BaseDimension {
  readonly name = 'test';
  readonly weight = 0.5;
  compute(node: any, _cpg: CPG): number {
    return (node.features['risk'] || 0) * 0.5;
  }
}

describe('BaseDimension', () => {
  test('name and weight are exposed', () => {
    const d = new TestDim();
    expect(d.name).toBe('test');
    expect(d.weight).toBe(0.5);
  });
  test('compute returns numeric contribution', () => {
    const d = new TestDim();
    expect(d.compute({ features: { risk: 1 } }, {} as any)).toBe(0.5);
  });
});
```

- [ ] **Step 2: Run test → expect FAIL**

Run: `bun test tests/unit/engine/dimensions/registry.test.ts`

- [ ] **Step 3: Create base.ts**

```typescript
// src/engine/dimensions/base.ts
/**
 * BaseDimension — abstract base for all cosmic-galaxy dimension detectors.
 * Spec: §4.2 Dimension Registry
 */
import type { CPG, CPGNode } from '../cpg/types.js';

export interface DimensionModule {
  readonly name: string;
  readonly weight: number;
  compute(node: CPGNode, cpg: CPG): number;
  explain?(node: CPGNode, cpg: CPG): string;
  llmPrompt?(node: CPGNode, cpg: CPG): string;
}

export abstract class BaseDimension implements DimensionModule {
  abstract readonly name: string;
  abstract readonly weight: number;
  abstract compute(node: CPGNode, cpg: CPG): number;
}
```

- [ ] **Step 4: Run test → expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/engine/dimensions/base.ts tests/unit/engine/dimensions/registry.test.ts
git commit -m "feat(dimensions): BaseDimension abstract class"
```

---

## Task 2: Dimension Registry

**Files:**
- Create: `src/engine/dimensions/registry.ts`
- Create: `src/engine/dimensions/ast-placeholder.ts`
- Test: extend `tests/unit/engine/dimensions/registry.test.ts`

- [ ] **Step 1: Extend test**

Add to `tests/unit/engine/dimensions/registry.test.ts`:

```typescript
import { DIMENSIONS, registerDimension, getEnabledDimensions, normalizeWeights } from '../../../../src/engine/dimensions/registry.js';

test('normalizeWeights rescales to sum=1', () => {
  const w = normalizeWeights({ a: 0.5, b: 0.3, c: 0 });
  expect(w.a + w.b).toBeCloseTo(1.0);
  expect(w.c).toBe(0);
});

test('getEnabledDimensions returns only enabled', () => {
  const dims = getEnabledDimensions({ ast: true, llm: false });
  expect(dims.length).toBeGreaterThan(0);
  expect(dims.every(d => d.name !== 'llm')).toBe(true);
});
```

- [ ] **Step 2: Run → expect FAIL**

- [ ] **Step 3: Implement registry**

```typescript
// src/engine/dimensions/registry.ts
/**
 * Dimension Registry — global catalog of cosmic-galaxy dimension detectors.
 * Spec: §4.2
 */
import { BaseDimension, type DimensionModule } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

class AstPlaceholderDim extends BaseDimension {
  readonly name = 'ast';
  readonly weight = 0.15;
  compute(node: CPGNode, _cpg: CPG): number {
    return Math.min(1, (node.features['complexity'] || 0) / 10);
  }
}

export const DIMENSIONS: Record<string, DimensionModule> = {
  ast: new AstPlaceholderDim(),
};

export function registerDimension(dim: DimensionModule): void {
  DIMENSIONS[dim.name] = dim;
}

export function getEnabledDimensions(flags: Record<string, boolean>): DimensionModule[] {
  return Object.values(DIMENSIONS).filter(d => flags[d.name] !== false);
}

export function normalizeWeights(weights: Record<string, number>): Record<string, number> {
  const total = Object.values(weights).reduce((s, w) => s + (w > 0 ? w : 0), 0);
  if (total === 0) return weights;
  const result: Record<string, number> = {};
  for (const [k, w] of Object.entries(weights)) result[k] = w > 0 ? w / total : 0;
  return result;
}
```

- [ ] **Step 4: Create ast-placeholder.ts**

```typescript
// src/engine/dimensions/ast-placeholder.ts
export { AstPlaceholderDim } from './registry.js';
```

- [ ] **Step 5: Run → expect PASS**

- [ ] **Step 6: Commit**

```bash
git add src/engine/dimensions/ tests/unit/engine/dimensions/registry.test.ts
git commit -m "feat(dimensions): registry with ast placeholder"
```

---

## Task 3: VuleConfig + YAML Loader

**Files:**
- Create: `src/engine/vule-config.ts`
- Create: `config/vule.yaml`
- Test: `tests/unit/engine/vule-config.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/engine/vule-config.test.ts
import { describe, expect, test } from 'bun:test';
import { loadConfig, defaultConfig, VuleConfig } from '../../../../src/engine/vule-config.js';

describe('VuleConfig', () => {
  test('defaultConfig has all required fields', () => {
    const c = defaultConfig();
    expect(c.weights).toBeDefined();
    expect(c.weights.taint).toBe(0.20);
    expect(c.thresholds.CRITICAL).toBe(0.85);
  });

  test('loadConfig parses YAML string', () => {
    const yaml = `
weights:
  taint: 0.5
  ast: 0.5
thresholds:
  LOW: 0.3
  MEDIUM: 0.5
  HIGH: 0.7
  CRITICAL: 0.9
`;
    const c = loadConfig(yaml);
    expect(c.weights.taint).toBe(0.5);
    expect(c.thresholds.CRITICAL).toBe(0.9);
  });

  test('loadConfig throws on invalid YAML', () => {
    expect(() => loadConfig(': bad: :')).toThrow();
  });
});
```

- [ ] **Step 2: Run → expect FAIL**

- [ ] **Step 3: Add `js-yaml` dependency**

```bash
bun add js-yaml
```

- [ ] **Step 4: Create config/vule.yaml**

```yaml
# Default VuleEngine configuration (cosmic-galaxy aligned)
uvrs:
  weights:
    taint: 0.20
    ast: 0.15
    llm: 0.10
    consensus: 0.10
    verify: 0.10
    chain: 0.10
    darkMatter: 0.08
    evolution: 0.05
    quantum: 0.07
    entropy: 0.05
  thresholds:
    LOW: 0.25
    MEDIUM: 0.50
    HIGH: 0.75
    CRITICAL: 0.85

dimensions:
  enabled:
    - ast

llm:
  provider: minimax
  model: MiniMax-M3
  maxFindings: 5
  verify: false
  consensusMode: failover

cache:
  enabled: true
  size: 1000
  persistPath: .vule-cache/

report:
  format: json
  savePath: cosmic_report
  topK: 20
  includeVisualization: false
```

- [ ] **Step 5: Create vule-config.ts**

```typescript
// src/engine/vule-config.ts
/**
 * VuleConfig — runtime configuration for VuleEngine.
 * Spec: §7.1 YAML configuration
 */
import yaml from 'js-yaml';
import { readFileSync, existsSync } from 'fs';

export interface UVRSWeightsConfig {
  taint: number; ast: number; llm: number; consensus: number;
  verify: number; chain: number; darkMatter: number;
  evolution: number; quantum: number; entropy: number;
}

export interface RiskThresholdsConfig {
  LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number;
}

export interface VuleConfig {
  weights: UVRSWeightsConfig;
  thresholds: RiskThresholdsConfig;
  dimensions: { enabled: string[] };
  llm: { provider: string; model: string; maxFindings: number; verify: boolean; consensusMode: 'failover' | 'consensus' };
  cache: { enabled: boolean; size: number; persistPath: string };
  report: { format: 'json' | 'html' | 'markdown'; savePath: string; topK: number; includeVisualization: boolean };
}

export function defaultConfig(): VuleConfig {
  return {
    weights: {
      taint: 0.20, ast: 0.15, llm: 0.10, consensus: 0.10, verify: 0.10,
      chain: 0.10, darkMatter: 0.08, evolution: 0.05, quantum: 0.07, entropy: 0.05,
    },
    thresholds: { LOW: 0.25, MEDIUM: 0.50, HIGH: 0.75, CRITICAL: 0.85 },
    dimensions: { enabled: ['ast'] },
    llm: { provider: 'minimax', model: 'MiniMax-M3', maxFindings: 5, verify: false, consensusMode: 'failover' },
    cache: { enabled: true, size: 1000, persistPath: '.vule-cache/' },
    report: { format: 'json', savePath: 'cosmic_report', topK: 20, includeVisualization: false },
  };
}

export function loadConfig(source: string | object, defaults: VuleConfig = defaultConfig()): VuleConfig {
  let parsed: any;
  if (typeof source === 'string') {
    if (existsSync(source)) parsed = yaml.load(readFileSync(source, 'utf-8'));
    else parsed = yaml.load(source);
  } else {
    parsed = source;
  }
  return {
    weights: { ...defaults.weights, ...(parsed?.uvrs?.weights || parsed?.weights || {}) },
    thresholds: { ...defaults.thresholds, ...(parsed?.uvrs?.thresholds || parsed?.thresholds || {}) },
    dimensions: { enabled: parsed?.dimensions?.enabled || defaults.dimensions.enabled },
    llm: { ...defaults.llm, ...(parsed?.llm || {}) },
    cache: { ...defaults.cache, ...(parsed?.cache || {}) },
    report: { ...defaults.report, ...(parsed?.report || {}) },
  };
}
```

- [ ] **Step 6: Run → expect PASS**

- [ ] **Step 7: Commit**

```bash
git add src/engine/vule-config.ts config/vule.yaml tests/unit/engine/vule-config.test.ts package.json bun.lock
git commit -m "feat(engine): VuleConfig with YAML loader + defaults"
```

---

## Task 4: VuleReport + Exporters

**Files:**
- Create: `src/engine/vule-report.ts`

- [ ] **Step 1: Create report types and JSON exporter**

```typescript
// src/engine/vule-report.ts
/**
 * VuleReport — analysis output and export to JSON/HTML/Markdown.
 * Spec: §4.1 + §6
 */
import type { CPGNode } from './cpg/types.js';
import { RiskLevel } from './uvrs.js';

export interface NodeReport {
  nodeId: string;
  file: string;
  line: number;
  code: string;
  uvrs: number;
  level: RiskLevel;
  dominantDimension: string;
  contributions: Record<string, number>;
}

export interface VuleReport {
  version: string;
  generatedAt: string;
  nodeCount: number;
  riskDistribution: Record<RiskLevel, number>;
  topRisk: NodeReport[];
  blackHoles?: string[];
  tornNodes?: string[];
}

export function makeNodeReport(
  node: CPGNode, uvrs: number, level: RiskLevel,
  dominant: string, contributions: Record<string, number>,
): NodeReport {
  return {
    nodeId: node.id, file: node.file, line: node.line, code: node.code,
    uvrs, level, dominantDimension: dominant, contributions,
  };
}

export function reportToJSON(report: VuleReport): string {
  return JSON.stringify(report, null, 2);
}

export function reportToMarkdown(report: VuleReport): string {
  const lines: string[] = [];
  lines.push(`# VuleEngine Report (v${report.version})`);
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push(`\n## Summary`);
  lines.push(`- Nodes: ${report.nodeCount}`);
  lines.push(`- Distribution: ${JSON.stringify(report.riskDistribution)}`);
  lines.push(`\n## Top ${report.topRisk.length} Risk Nodes`);
  lines.push(`| Rank | ID | File:Line | UVRS | Level | Dominant |`);
  lines.push(`|------|----|-----------|------|-------|----------|`);
  report.topRisk.forEach((n, i) => {
    lines.push(`| ${i + 1} | ${n.nodeId} | ${n.file}:${n.line} | ${n.uvrs.toFixed(3)} | ${n.level} | ${n.dominantDimension} |`);
  });
  return lines.join('\n');
}
```

- [ ] **Step 2: Verify compile**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head`

- [ ] **Step 3: Commit**

```bash
git add src/engine/vule-report.ts
git commit -m "feat(engine): VuleReport types + JSON/MD exporters"
```

---

## Task 5: VuleEngine Core Class

**Files:**
- Create: `src/engine/vule-engine.ts`
- Test: `tests/unit/engine/vule-engine.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/engine/vule-engine.test.ts
import { describe, expect, test } from 'bun:test';
import { VuleEngine } from '../../../../src/engine/vule-engine.js';
import { CPGBuilder } from '../../../../src/engine/cpg/builder.js';
import type { ProgramGraph } from '../../../../src/engine/program-graph.js';

function makePG(): ProgramGraph {
  return {
    nodes: new Map([
      ['n1', { id: 'n1', type: 'variable', code: '$_GET["x"]', lineStart: 1, lineEnd: 1, properties: new Map() }],
      ['n2', { id: 'n2', type: 'call', code: 'mysql_query($q)', lineStart: 2, lineEnd: 2, properties: new Map() }],
    ]),
    edges: [{ source: 'n1', target: 'n2', type: 'DFG' }],
    nodeCount: 2, edgeCount: 1, edgeTypeCounts: {} as any,
    filePath: 'sqli.php', language: 'php',
  } as any;
}

describe('VuleEngine', () => {
  test('constructs with CPG + sinks + config', () => {
    const cpg = new CPGBuilder('php').build(makePG());
    const engine = new VuleEngine(cpg, ['n2'], [], undefined);
    expect(engine.cpg.nodes.size).toBe(2);
  });

  test('computeUVRS returns score in [0, 1)', () => {
    const cpg = new CPGBuilder('php').build(makePG());
    const engine = new VuleEngine(cpg, ['n2'], []);
    const r = engine.computeUVRS('n2');
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThan(1.0);
  });

  test('analyze returns VuleReport', () => {
    const cpg = new CPGBuilder('php').build(makePG());
    const engine = new VuleEngine(cpg, ['n2'], []);
    const report = engine.analyze();
    expect(report.nodeCount).toBe(2);
    expect(report.topRisk.length).toBeGreaterThan(0);
  });

  test('topRiskNodes returns sorted by UVRS desc', () => {
    const cpg = new CPGBuilder('php').build(makePG());
    const engine = new VuleEngine(cpg, ['n2'], []);
    const top = engine.topRiskNodes(2);
    if (top.length >= 2) expect(top[0].uvrs).toBeGreaterThanOrEqual(top[1].uvrs);
  });

  test('exportReport writes JSON file', () => {
    const cpg = new CPGBuilder('php').build(makePG());
    const engine = new VuleEngine(cpg, ['n2'], []);
    const path = engine.exportReport('/tmp/vule-test-report.json');
    expect(path).toContain('vule-test-report.json');
  });
});
```

- [ ] **Step 2: Run → expect FAIL**

- [ ] **Step 3: Implement VuleEngine**

```typescript
// src/engine/vule-engine.ts
/**
 * VuleEngine — unified entry point for cosmic-galaxy dimension analysis.
 * Spec: §4.1
 */
import type { CPG, CPGNode } from './cpg/types.js';
import { UVRS, RiskLevel, type UVRSComponents } from './uvrs.js';
import { DIMENSIONS, getEnabledDimensions } from './dimensions/registry.js';
import { VuleConfig, defaultConfig, loadConfig } from './vule-config.js';
import { VuleReport, NodeReport, makeNodeReport, reportToJSON } from './vule-report.js';
import { writeFileSync } from 'fs';

export class VuleEngine {
  readonly cpg: CPG;
  readonly sinks: string[];
  readonly securityAPIs: string[];
  readonly config: VuleConfig;
  private uvrs: UVRS;
  private _scores?: Map<string, { score: number; level: RiskLevel; dominant: string; contributions: Record<string, number> }>;

  constructor(cpg: CPG, sinks: string[] = [], securityAPIs: string[] = [], config?: VuleConfig | string) {
    this.cpg = cpg;
    this.sinks = sinks;
    this.securityAPIs = securityAPIs;
    this.config = typeof config === 'string' ? loadConfig(config) : (config || defaultConfig());
    this.uvrs = new UVRS(this.config.weights, this.config.thresholds);
  }

  computeUVRS(nodeId: string): { score: number; level: RiskLevel; dominant: string; contributions: Record<string, number> } {
    const node = this.cpg.getNode(nodeId);
    if (!node) return { score: 0, level: RiskLevel.LOW, dominant: 'none', contributions: {} };
    const components = this.computeComponents(node);
    const result = this.uvrs.compute(components);
    return { score: result.score, level: result.level, dominant: result.dominantDimension.name, contributions: result.contributions };
  }

  private computeComponents(node: CPGNode): UVRSComponents {
    const components: UVRSComponents = {};
    const enabled = getEnabledDimensions(
      Object.fromEntries(this.config.dimensions.enabled.map(n => [n, true]))
    );
    for (const dim of enabled) {
      try {
        const v = dim.compute(node, this.cpg);
        components[dim.name as keyof UVRSComponents] = Math.max(0, Math.min(1, v));
      } catch {
        // skip failed dimension
      }
    }
    return components;
  }

  analyze(): VuleReport {
    const scores = new Map<string, { score: number; level: RiskLevel; dominant: string; contributions: Record<string, number> }>();
    for (const id of this.cpg.nodes.keys()) {
      scores.set(id, this.computeUVRS(id));
    }
    this._scores = scores;
    const topK = this.config.report.topK;
    const sorted = Array.from(scores.entries())
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, topK);
    const topRisk: NodeReport[] = sorted.map(([id, r]) => {
      const n = this.cpg.getNode(id)!;
      return makeNodeReport(n, r.score, r.level, r.dominant, r.contributions);
    });
    const dist = this.uvrs.getRiskDistribution(Array.from(scores.values()).map(s => s.score));
    return {
      version: '0.3.0',
      generatedAt: new Date().toISOString(),
      nodeCount: this.cpg.nodes.size,
      riskDistribution: dist,
      topRisk,
    };
  }

  topRiskNodes(k?: number): NodeReport[] {
    const report = this.analyze();
    return report.topRisk.slice(0, k ?? this.config.report.topK);
  }

  exportReport(path?: string): string {
    const report = this.analyze();
    const out = path || `${this.config.report.savePath}.${this.config.report.format}`;
    writeFileSync(out, reportToJSON(report));
    return out;
  }
}
```

- [ ] **Step 4: Run → expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/engine/vule-engine.ts tests/unit/engine/vule-engine.test.ts
git commit -m "feat(engine): VuleEngine unified entry + UVRS integration"
```

---

## Task 6: Run All Tests + Type Check

- [ ] **Step 1: Run all Sprint 2 tests**

Run: `bun test tests/unit/engine/vule-*.test.ts tests/unit/engine/dimensions/ tests/unit/engine/vule-config.test.ts`
Expected: 12 tests PASS

- [ ] **Step 2: Type check**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head`

- [ ] **Step 3: Commit if any fixups**

---

## Definition of Done (Sprint 2)

- [ ] VuleEngine class works end-to-end (CPG → UVRS → report)
- [ ] YAML config loads correctly
- [ ] 12 tests passing
- [ ] 0 new TypeScript errors
- [ ] `vule.engine` API exported from `src/engine/vule-engine.ts`

**Next sprint**: Sprint 3 — implement the 6 P0 core dimensions (gravity, kepler, orbital, nbody + extensions of existing taint/LLM modules).