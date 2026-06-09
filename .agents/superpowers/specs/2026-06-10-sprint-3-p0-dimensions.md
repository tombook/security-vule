# Sprint 3: P0 Core Dimensions Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the 4 P0 cosmic-galaxy dimension detectors: 引力场 (gravity/taint), 开普勒 (kepler distance), 轨道六要素 (orbital elements), N体 (nbody/multi-LLM consensus). Each registers into `DIMENSIONS` registry and is consumed by `VuleEngine.computeUVRS()`.

**Architecture:** Each dimension extends `BaseDimension` and implements `compute(node, cpg) -> number`. Reads CPG via existing query methods. Each dimension has unit tests + theory markdown doc.

**Tech Stack:** TypeScript, Bun, existing `LLMAgent` for nbody dimension.

**Spec reference:** §3.1 P0 dimensions (gravity, kepler, orbital, nbody).

**Depends on:** Sprint 1 (CPG), Sprint 2 (VuleEngine + registry).

---

## File Structure

| File | Responsibility | Lines |
|------|---------------|-------|
| `src/engine/dimensions/gravity.ts` | 引力场: F = Γ·W_src·W_sink/d² | ~120 |
| `src/engine/dimensions/kepler.ts` | 开普勒: distance distribution + eccentricity | ~80 |
| `src/engine/dimensions/orbital.ts` | 6 orbital elements (a/e/i/Ω/ω/θ) | ~150 |
| `src/engine/dimensions/nbody.ts` | N体: multi-LLM consensus | ~100 |
| `theory/dimensions/kepler.md` | Theory doc | ~40 |
| `theory/dimensions/orbital.md` | Theory doc | ~40 |
| `theory/dimensions/nbody.md` | Theory doc | ~40 |
| `tests/unit/engine/dimensions/gravity.test.ts` | Tests | ~150 |
| `tests/unit/engine/dimensions/kepler.test.ts` | Tests | ~120 |
| `tests/unit/engine/dimensions/orbital.test.ts` | Tests | ~150 |
| `tests/unit/engine/dimensions/nbody.test.ts` | Tests | ~100 |

**Total**: ~11 files, ~1090 lines.

---

## Task 1: 引力场 (Gravity) Dimension

**Files:**
- Create: `src/engine/dimensions/gravity.ts`
- Test: `tests/unit/engine/dimensions/gravity.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/engine/dimensions/gravity.test.ts
import { describe, expect, test } from 'bun:test';
import { GravityDimension } from '../../../../src/engine/dimensions/gravity.js';
import { createCPG, type CPG } from '../../../../src/engine/cpg/types.js';

function cpgWithSink(): CPG {
  return createCPG(
    new Map([
      ['src', { id: 'src', type: 'var', file: 'a.php', line: 1, col: 0, code: '$_GET["x"]', language: 'php', features: { sensitivity: 1 } }],
      ['mid', { id: 'mid', type: 'stmt', file: 'a.php', line: 2, col: 0, code: 'process($x)', language: 'php', features: {} }],
      ['sink', { id: 'sink', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'mysql_query($x)', language: 'php', features: { is_sink: 1, dangerousness: 0.9 } }],
    ]),
    [
      { source: 'src', target: 'mid', kind: 'data' },
      { source: 'mid', target: 'sink', kind: 'data' },
    ],
    'php',
  );
}

describe('GravityDimension', () => {
  test('weight is 0.20 (highest cosmic-galaxy priority)', () => {
    expect(new GravityDimension().weight).toBe(0.20);
  });
  test('sink node gets highest gravity risk', () => {
    const cpg = cpgWithSink();
    const dim = new GravityDimension();
    const sinkScore = dim.compute(cpg.getNode('sink')!, cpg);
    const srcScore = dim.compute(cpg.getNode('src')!, cpg);
    expect(sinkScore).toBeGreaterThan(srcScore);
  });
  test('non-sink non-source node returns low risk', () => {
    const cpg = cpgWithSink();
    const dim = new GravityDimension();
    const midScore = dim.compute(cpg.getNode('mid')!, cpg);
    expect(midScore).toBeLessThan(0.5);
  });
  test('output is clamped to [0,1]', () => {
    const cpg = cpgWithSink();
    const dim = new GravityDimension();
    for (const node of cpg.nodes.values()) {
      const v = dim.compute(node, cpg);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });
});
```

- [ ] **Step 2: Run → expect FAIL**

- [ ] **Step 3: Implement**

```typescript
// src/engine/dimensions/gravity.ts
/**
 * Dimension #1: 引力场 (Gravity Field)
 * Formula: F_ij = Γ · (W_src · W_sink) / d_ij²
 * Spec: §3.1, theory/dimensions/gravity.md
 */
import { BaseDimension } from './base.js';
import { type CPG, type CPGNode } from '../cpg/types.js';
import { shortestPath } from '../cpg/queries.js';

const GAMMA = 0.20;

export class GravityDimension extends BaseDimension {
  readonly name = 'gravity';
  readonly weight = 0.20;

  compute(node: CPGNode, cpg: CPG): number {
    const sinks = cpg.sinkNodes();
    if (sinks.length === 0) return 0;
    let maxRisk = 0;
    for (const sink of sinks) {
      if (sink.id === node.id) {
        // Node IS a sink: risk from incoming sources
        const sources = cpg.sourcesFor(sink.id);
        for (const src of sources) {
          const wSrc = (src.features['sensitivity'] || 0.5);
          const wSink = (sink.features['dangerousness'] || 0.7);
          const d = Math.max(1, cpg.shortestPath(src.id, sink.id)?.length || 1);
          const risk = GAMMA * (wSrc * wSink) / (d * d);
          maxRisk = Math.max(maxRisk, risk);
        }
      } else {
        const path = cpg.shortestPath(node.id, sink.id);
        if (!path) continue;
        const wSrc = (node.features['sensitivity'] || 0.5);
        const wSink = (sink.features['dangerousness'] || 0.7);
        const d = path.length;
        const risk = GAMMA * (wSrc * wSink) / (d * d);
        maxRisk = Math.max(maxRisk, risk);
      }
    }
    return Math.min(1, maxRisk);
  }
}
```

- [ ] **Step 4: Run → expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/engine/dimensions/gravity.ts tests/unit/engine/dimensions/gravity.test.ts
git commit -m "feat(dimensions): 引力场 (gravity) — taint-based risk propagation"
```

---

## Task 2: 开普勒 (Kepler) Dimension

**Files:**
- Create: `src/engine/dimensions/kepler.ts`
- Create: `theory/dimensions/kepler.md`
- Test: `tests/unit/engine/dimensions/kepler.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #2: 开普勒轨道 (Kepler Orbit)

**Cosmic-galaxy formula**: `r(θ) = a(1-e²)/(1+e·cosθ)`

**Code mapping**:
- `r(θ)` — probability of vulnerability at graph distance θ
- `a` — mean shortest path from node to sinks
- `e` — eccentricity = std(distances) / mean(distances)
- `θ` — graph embedding angle (via node2vec)

**security-vule implementation**:
- For each node: collect distances to all sinks
- `risk = 1 / (1 + mean_distance)` if any sink is reachable, else 0
- Eccentricity > 1 (hyperbolic orbit) increases risk
```

- [ ] **Step 2: Failing test**

```typescript
// tests/unit/engine/dimensions/kepler.test.ts
import { describe, expect, test } from 'bun:test';
import { KeplerDimension } from '../../../../src/engine/dimensions/kepler.js';
import { createCPG, type CPG } from '../../../../src/engine/cpg/types.js';

function chainCPG(): CPG {
  return createCPG(
    new Map([
      ['n1', { id: 'n1', type: 'var', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }],
      ['n2', { id: 'n2', type: 'stmt', file: 'a.php', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ['n3', { id: 'n3', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'sink()', language: 'php', features: { is_sink: 1 } }],
    ]),
    [
      { source: 'n1', target: 'n2', kind: 'data' },
      { source: 'n2', target: 'n3', kind: 'data' },
    ],
    'php',
  );
}

describe('KeplerDimension', () => {
  test('weight is 0.15', () => {
    expect(new KeplerDimension().weight).toBe(0.15);
  });
  test('node closer to sink has higher score', () => {
    const cpg = chainCPG();
    const dim = new KeplerDimension();
    const n2 = dim.compute(cpg.getNode('n2')!, cpg);
    const n1 = dim.compute(cpg.getNode('n1')!, cpg);
    expect(n2).toBeGreaterThan(n1);
  });
  test('isolated node returns 0', () => {
    const cpg = createCPG(
      new Map([['iso', { id: 'iso', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    const dim = new KeplerDimension();
    expect(dim.compute(cpg.getNode('iso')!, cpg)).toBe(0);
  });
  test('hyperbolic eccentricity (>1) boosts risk', () => {
    // 3 sinks at distances [1, 5, 10] → high eccentricity
    const cpg = createCPG(
      new Map([
        ['src', { id: 'src', type: 'var', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['s1', { id: 's1', type: 'stmt', file: 'a.php', line: 2, col: 0, code: 'sink1', language: 'php', features: { is_sink: 1 } }],
        ['s2', { id: 's2', type: 'stmt', file: 'a.php', line: 6, col: 0, code: 'sink2', language: 'php', features: { is_sink: 1 } }],
        ['s3', { id: 's3', type: 'stmt', file: 'a.php', line: 11, col: 0, code: 'sink3', language: 'php', features: { is_sink: 1 } }],
      ]),
      [
        { source: 'src', target: 's1', kind: 'data' },
        { source: 'src', target: 's2', kind: 'data' },
        { source: 'src', target: 's3', kind: 'data' },
      ], 'php'
    );
    const dim = new KeplerDimension();
    const v = dim.compute(cpg.getNode('src')!, cpg);
    expect(v).toBeGreaterThan(0.1);
  });
});
```

- [ ] **Step 3: Run → expect FAIL**

- [ ] **Step 4: Implement**

```typescript
// src/engine/dimensions/kepler.ts
/**
 * Dimension #2: 开普勒轨道 (Kepler Orbit)
 * Formula: r(θ) = a(1-e²)/(1+e·cosθ)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class KeplerDimension extends BaseDimension {
  readonly name = 'kepler';
  readonly weight = 0.15;

  compute(node: CPGNode, cpg: CPG): number {
    const sinks = cpg.sinkNodes();
    if (sinks.length === 0) return 0;
    const distances: number[] = [];
    for (const sink of sinks) {
      if (sink.id === node.id) { distances.push(0); continue; }
      const path = cpg.shortestPath(node.id, sink.id);
      if (path) distances.push(path.length);
    }
    if (distances.length === 0) return 0;
    const mean = distances.reduce((s, x) => s + x, 0) / distances.length;
    const variance = distances.reduce((s, x) => s + (x - mean) ** 2, 0) / distances.length;
    const std = Math.sqrt(variance);
    const e = mean > 0 ? std / mean : 0;
    // Base risk: inverse of mean distance
    const baseRisk = mean > 0 ? 1 / (1 + mean) : 1;
    // Hyperbolic boost (e > 1 = unbalanced sinks)
    const boost = e > 1 ? (e - 1) * 0.2 : 0;
    return Math.min(1, baseRisk + boost);
  }
}
```

- [ ] **Step 5: Run → expect PASS**

- [ ] **Step 6: Commit**

```bash
git add src/engine/dimensions/kepler.ts theory/dimensions/kepler.md tests/unit/engine/dimensions/kepler.test.ts
git commit -m "feat(dimensions): 开普勒 (kepler) — distance distribution risk"
```

---

## Task 3: 轨道六要素 (Orbital Elements)

**Files:**
- Create: `src/engine/dimensions/orbital.ts`
- Create: `theory/dimensions/orbital.md`
- Test: `tests/unit/engine/dimensions/orbital.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #3: 轨道六要素 (Orbital Elements)

**Cosmic-galaxy formulas**: `[a, e, i, Ω, ω, θ]` — six-element feature vector

**Code mapping**:
- `a` (semi-major axis): mean shortest path to all sinks
- `e` (eccentricity): std of [betweenness, closeness, eigenvector, pagerank] / mean
- `i` (inclination): arccos(neighbor_overlap_with_security_apis / total_neighbors)
- `Ω` (longitude of ascending node): pageRank angle (placeholder)
- `ω` (argument of periapsis): argmax of risk gradient
- `θ` (true anomaly): current UVRS × time decay (placeholder: UVRS-derived)

**security-vule implementation**:
- Reads from CPG node features (pagerank/betweenness precomputed)
- Risk = f(a, e, i) — first three elements that can be derived from CPG
```

- [ ] **Step 2: Failing test**

```typescript
// tests/unit/engine/dimensions/orbital.test.ts
import { describe, expect, test } from 'bun:test';
import { OrbitalDimension } from '../../../../src/engine/dimensions/orbital.js';
import { createCPG, type CPG } from '../../../../src/engine/cpg/types.js';

describe('OrbitalDimension', () => {
  test('weight is 0.10', () => {
    expect(new OrbitalDimension().weight).toBe(0.10);
  });
  test('centrality-loaded node returns higher eccentricity', () => {
    const cpg = createCPG(
      new Map([
        ['hub', { id: 'hub', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: { pagerank: 0.8, betweenness: 0.9 } }],
        ['leaf', { id: 'leaf', type: 'stmt', file: 'a.php', line: 2, col: 0, code: '', language: 'php', features: { pagerank: 0.05, betweenness: 0.0 } }],
        ['s', { id: 's', type: 'stmt', file: 'a.php', line: 3, col: 0, code: 'sink', language: 'php', features: { is_sink: 1 } }],
      ]),
      [
        { source: 'leaf', target: 'hub', kind: 'data' },
        { source: 'hub', target: 's', kind: 'data' },
      ], 'php'
    );
    const dim = new OrbitalDimension();
    const hub = dim.compute(cpg.getNode('hub')!, cpg);
    const leaf = dim.compute(cpg.getNode('leaf')!, cpg);
    expect(hub).toBeGreaterThan(leaf);
  });
  test('empty features returns 0', () => {
    const cpg = createCPG(
      new Map([['x', { id: 'x', type: 'stmt', file: 'a.php', line: 1, col: 0, code: '', language: 'php', features: {} }]]),
      [], 'php'
    );
    expect(new OrbitalDimension().compute(cpg.getNode('x')!, cpg)).toBe(0);
  });
});
```

- [ ] **Step 3: Run → expect FAIL**

- [ ] **Step 4: Implement**

```typescript
// src/engine/dimensions/orbital.ts
/**
 * Dimension #3: 轨道六要素 (Orbital Elements)
 * Spec: §3.1
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class OrbitalDimension extends BaseDimension {
  readonly name = 'orbital';
  readonly weight = 0.10;

  compute(node: CPGNode, cpg: CPG): number {
    const pr = node.features['pagerank'] ?? 0;
    const bc = node.features['betweenness'] ?? 0;
    const ec = node.features['eigenvector'] ?? 0;
    const cc = node.features['closeness'] ?? 0;
    const centralities = [pr, bc, ec, cc];
    const nonZero = centralities.filter(x => x > 0);
    if (nonZero.length === 0) return 0;
    const mean = nonZero.reduce((s, x) => s + x, 0) / nonZero.length;
    const std = Math.sqrt(nonZero.reduce((s, x) => s + (x - mean) ** 2, 0) / nonZero.length);
    const e = mean > 0 ? std / mean : 0;
    // Higher eccentricity = more central = higher risk
    // Also incorporate pagerank directly
    const prRisk = Math.min(1, pr * 5);
    const eRisk = Math.min(1, e);
    return Math.min(1, (prRisk * 0.6 + eRisk * 0.4));
  }
}
```

- [ ] **Step 5: Run → expect PASS**

- [ ] **Step 6: Commit**

```bash
git add src/engine/dimensions/orbital.ts theory/dimensions/orbital.md tests/unit/engine/dimensions/orbital.test.ts
git commit -m "feat(dimensions): 轨道六要素 (orbital) — centrality-based risk"
```

---

## Task 4: N体 (N-Body / Multi-LLM Consensus)

**Files:**
- Create: `src/engine/dimensions/nbody.ts`
- Create: `theory/dimensions/nbody.md`
- Test: `tests/unit/engine/dimensions/nbody.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #4: N体 (N-Body Multi-Model Consensus)

**Cosmic-galaxy formula**: `m_i · d²r_i/dt² = Σ_{j≠i} G·m_j·(r_j-r_i)/|r_j-r_i|³`

**Code mapping**: Multi-LLM consensus (already implemented in `src/llm/consensus.ts`)
- Each LLM is a "body" with mass = confidence
- Consensus = pairwise gravitational attraction
- Barnes-Hut O(N log N) optimization for many LLMs

**security-vule implementation**:
- Reuses `runConsensus()` from `src/llm/consensus.ts`
- Returns agreement ratio (0-1) as dimension contribution
- Without LLM call: defaults to 0 (no consensus info)
```

- [ ] **Step 2: Failing test**

```typescript
// tests/unit/engine/dimensions/nbody.test.ts
import { describe, expect, test } from 'bun:test';
import { NBodyDimension } from '../../../../src/engine/dimensions/nbody.js';

describe('NBodyDimension', () => {
  test('weight is 0.10', () => {
    expect(new NBodyDimension().weight).toBe(0.10);
  });
  test('without consensus context, returns 0', () => {
    const dim = new NBodyDimension();
    expect(dim.compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }, {} as any)).toBe(0);
  });
  test('with consensusMap, returns agreement score', () => {
    const dim = new NBodyDimension();
    dim.setConsensusContext({ x: 0.85 });
    expect(dim.compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }, {} as any)).toBe(0.85);
  });
  test('clamps to [0,1]', () => {
    const dim = new NBodyDimension();
    dim.setConsensusContext({ y: 1.5 });
    expect(dim.compute({ id: 'y', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }, {} as any)).toBeLessThanOrEqual(1);
  });
});
```

- [ ] **Step 3: Run → expect FAIL**

- [ ] **Step 4: Implement**

```typescript
// src/engine/dimensions/nbody.ts
/**
 * Dimension #4: N体 (Multi-LLM Consensus)
 * Spec: §3.1; uses src/llm/consensus.ts
 */
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class NBodyDimension extends BaseDimension {
  readonly name = 'nbody';
  readonly weight = 0.10;
  private consensusMap: Map<string, number> = new Map();

  setConsensusContext(map: Record<string, number>): void {
    this.consensusMap = new Map(Object.entries(map));
  }

  compute(node: CPGNode, _cpg: CPG): number {
    const agreement = this.consensusMap.get(node.id);
    if (agreement === undefined) return 0;
    return Math.max(0, Math.min(1, agreement));
  }
}
```

- [ ] **Step 5: Run → expect PASS**

- [ ] **Step 6: Commit**

```bash
git add src/engine/dimensions/nbody.ts theory/dimensions/nbody.md tests/unit/engine/dimensions/nbody.test.ts
git commit -m "feat(dimensions): N体 (nbody) — multi-LLM consensus"
```

---

## Task 5: Register All P0 Dimensions + Integration Test

**Files:**
- Modify: `src/engine/dimensions/registry.ts`
- Create: `tests/unit/engine/dimensions/p0-integration.test.ts`

- [ ] **Step 1: Update registry to register all P0 dimensions**

In `src/engine/dimensions/registry.ts`, replace the `AstPlaceholderDim` block with:

```typescript
import { GravityDimension } from './gravity.js';
import { KeplerDimension } from './kepler.js';
import { OrbitalDimension } from './orbital.js';
import { NBodyDimension } from './nbody.js';

class AstPlaceholderDim extends BaseDimension {
  readonly name = 'ast';
  readonly weight = 0.15;
  compute(node: CPGNode, _cpg: CPG): number {
    return Math.min(1, (node.features['complexity'] || 0) / 10);
  }
}

export const DIMENSIONS: Record<string, DimensionModule> = {
  ast: new AstPlaceholderDim(),
  gravity: new GravityDimension(),
  kepler: new KeplerDimension(),
  orbital: new OrbitalDimension(),
  nbody: new NBodyDimension(),
};
```

- [ ] **Step 2: Add integration test**

```typescript
// tests/unit/engine/dimensions/p0-integration.test.ts
import { describe, expect, test } from 'bun:test';
import { DIMENSIONS } from '../../../../src/engine/dimensions/registry.js';
import { VuleEngine } from '../../../../src/engine/vule-engine.js';
import { CPGBuilder } from '../../../../src/engine/cpg/builder.js';
import { defaultConfig } from '../../../../src/engine/vule-config.js';
import type { ProgramGraph } from '../../../../src/engine/program-graph.js';

describe('P0 dimensions integration', () => {
  test('all 4 P0 dimensions registered', () => {
    expect(DIMENSIONS.gravity).toBeDefined();
    expect(DIMENSIONS.kepler).toBeDefined();
    expect(DIMENSIONS.orbital).toBeDefined();
    expect(DIMENSIONS.nbody).toBeDefined();
  });
  test('weights sum to 0.55 (gravity+kepler+orbital+nbody)', () => {
    const sum = ['gravity', 'kepler', 'orbital', 'nbody'].reduce((s, k) => s + DIMENSIONS[k].weight, 0);
    expect(sum).toBeCloseTo(0.55);
  });
  test('VuleEngine uses P0 dimensions on a tainted PHP file', () => {
    const pg: ProgramGraph = {
      nodes: new Map([
        ['n1', { id: 'n1', type: 'variable', code: '$_GET["x"]', lineStart: 1, lineEnd: 1, properties: new Map() }],
        ['n2', { id: 'n2', type: 'call', code: 'mysql_query($x)', lineStart: 2, lineEnd: 2, properties: new Map() }],
      ]),
      edges: [{ source: 'n1', target: 'n2', type: 'DFG' }],
      nodeCount: 2, edgeCount: 1, edgeTypeCounts: {} as any,
      filePath: 'sqli.php', language: 'php',
    } as any;
    const cpg = new CPGBuilder('php').build(pg);
    const cfg = defaultConfig();
    cfg.dimensions.enabled = ['gravity', 'kepler', 'orbital', 'nbody'];
    const engine = new VuleEngine(cpg, ['n2'], [], cfg);
    const report = engine.analyze();
    expect(report.topRisk.length).toBe(2);
    // mysql_query (sink) should be top risk
    expect(report.topRisk[0].nodeId).toBe('n2');
    expect(report.topRisk[0].uvrs).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/registry.ts tests/unit/engine/dimensions/p0-integration.test.ts
git commit -m "feat(dimensions): register P0 dimensions + integration test"
```

---

## Task 6: Run All Sprint 3 Tests

- [ ] **Step 1: Run all dimension tests**

Run: `bun test tests/unit/engine/dimensions/`
Expected: 17 tests PASS (4 gravity + 4 kepler + 3 orbital + 4 nbody + 3 integration − 1 = 17)

- [ ] **Step 2: Type check**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head`

- [ ] **Step 3: Commit if any fixups**

---

## Definition of Done (Sprint 3)

- [ ] 4 P0 dimensions implemented (gravity, kepler, orbital, nbody)
- [ ] All registered in `DIMENSIONS`
- [ ] 17 tests passing
- [ ] Integration test confirms VuleEngine uses them on a PHP fixture
- [ ] 3 theory docs written (`kepler.md`, `orbital.md`, `nbody.md`)
- [ ] 0 new TypeScript errors

**Next sprint**: Sprint 4 — P1 dimensions (perturbation, tidal, relativistic, darkMatter, entropy) + 3 P2 dimensions.