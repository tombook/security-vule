# Sprint 4: P1 + P2 Dimensions Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 5 P1 dimensions (perturbation, tidal, relativistic, darkMatter, entropy) and 3 P2 dimensions (quantum, topology, information). All register into `DIMENSIONS`, all have theory docs + tests.

**Architecture:** Same pattern as Sprint 3. Each dimension extends `BaseDimension`, reads CPG, returns 0-1. P1 dimensions use AST metrics; P2 dimensions are simpler heuristic checks.

**Spec reference:** §3.1 P1 + P2 dimensions.

**Depends on:** Sprint 1 (CPG), Sprint 3 (registry established).

---

## File Structure

| File | Responsibility | Lines |
|------|---------------|-------|
| `src/engine/dimensions/perturbation.ts` | P1: 摄动 | ~80 |
| `src/engine/dimensions/tidal.ts` | P1: 潮汐 (vulnerability chains) | ~100 |
| `src/engine/dimensions/relativistic.ts` | P1: 相对论 (nesting depth) | ~80 |
| `src/engine/dimensions/dark-matter.ts` | P1: 暗物质 (hidden deps) | ~100 |
| `src/engine/dimensions/entropy.ts` | P1: 熵增 (code entropy) | ~80 |
| `src/engine/dimensions/quantum.ts` | P2: 量子 (race condition risk) | ~60 |
| `src/engine/dimensions/topology.ts` | P2: 拓扑 (cycles/loops) | ~80 |
| `src/engine/dimensions/information.ts` | P2: 信息论 (Shannon) | ~60 |
| `theory/dimensions/*.md` (8 files) | Theory docs | ~320 |
| `tests/unit/engine/dimensions/{name}.test.ts` (8 files) | Tests | ~640 |

**Total**: ~25 files, ~1600 lines. Split into chunks per Task.

---

## Task 1: 摄动 (Perturbation) — P1

**Files:**
- Create: `src/engine/dimensions/perturbation.ts`
- Create: `theory/dimensions/perturbation.md`
- Test: `tests/unit/engine/dimensions/perturbation.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #5: 摄动理论 (Perturbation Theory)

**Cosmic-galaxy formula**: `da/dt = (2/(n²a))·∂R/∂M`

**Code mapping**: Long-term code evolution drift risk
- ΔLOC, complexity_delta, coupling_change as perturbation R
- Tracks per-file change history (git)

**security-vule implementation**:
- Without git history, uses static `churn` feature (if set externally)
- Risk = churn × current_complexity
```

- [ ] **Step 2: Failing test + implementation**

```typescript
// src/engine/dimensions/perturbation.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class PerturbationDimension extends BaseDimension {
  readonly name = 'perturbation';
  readonly weight = 0.05;

  compute(node: CPGNode, _cpg: CPG): number {
    const churn = node.features['churn'] || 0;
    const complexity = node.features['complexity'] || 0;
    const risk = (churn / 100) * (complexity / 10);
    return Math.min(1, risk);
  }
}
```

```typescript
// tests/unit/engine/dimensions/perturbation.test.ts
import { describe, expect, test } from 'bun:test';
import { PerturbationDimension } from '../../../../src/engine/dimensions/perturbation.js';

describe('PerturbationDimension', () => {
  test('weight is 0.05', () => expect(new PerturbationDimension().weight).toBe(0.05));
  test('zero churn = zero risk', () => {
    const dim = new PerturbationDimension();
    expect(dim.compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { complexity: 5 } }, {} as any)).toBe(0);
  });
  test('high churn + high complexity = high risk', () => {
    const dim = new PerturbationDimension();
    const v = dim.compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { churn: 1000, complexity: 10 } }, {} as any);
    expect(v).toBe(1);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/perturbation.ts theory/dimensions/perturbation.md tests/unit/engine/dimensions/perturbation.test.ts
git commit -m "feat(dimensions): 摄动 (perturbation) — code churn risk"
```

---

## Task 2: 潮汐 (Tidal) — P1

**Files:**
- Create: `src/engine/dimensions/tidal.ts`
- Create: `theory/dimensions/tidal.md`
- Test: `tests/unit/engine/dimensions/tidal.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #6: 潮汐力 (Tidal Force)

**Cosmic-galaxy formula**: `F_tidal = 2·Γ·W_A·W_B·C_coupling/d³`
**Roche limit**: `d_Roche = C_coupling·(2·Defense(A)/Defense(B))^(1/3)`

**Code mapping**: Multi-sink vulnerability chain risk
- W_A, W_B = sink weights; C_coupling = shared ancestor coupling
- d³ decay: closer sinks couple much more strongly

**security-vule implementation**:
- For each pair of sinks within distance ≤ 3: compute tidal coupling
- Risk = count of close-sink pairs × coupling strength
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/tidal.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TidalDimension extends BaseDimension {
  readonly name = 'tidal';
  readonly weight = 0.10;

  compute(node: CPGNode, cpg: CPG): number {
    const sinks = cpg.sinkNodes();
    if (sinks.length < 2) return 0;
    let risk = 0;
    for (let i = 0; i < sinks.length; i++) {
      for (let j = i + 1; j < sinks.length; j++) {
        const path = cpg.shortestPath(sinks[i].id, sinks[j].id);
        if (path && path.length <= 3) {
          const d = path.length;
          const coupling = 1 / (d * d * d);
          risk += coupling;
        }
      }
    }
    return Math.min(1, risk * 0.3);
  }
}
```

```typescript
// tests/unit/engine/dimensions/tidal.test.ts
import { describe, expect, test } from 'bun:test';
import { TidalDimension } from '../../../../src/engine/dimensions/tidal.js';
import { createCPG } from '../../../../src/engine/cpg/types.js';

describe('TidalDimension', () => {
  test('weight is 0.10', () => expect(new TidalDimension().weight).toBe(0.10));
  test('single sink = 0 risk', () => {
    const cpg = createCPG(
      new Map([['s', { id: 's', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { is_sink: 1 } }]]),
      [], 'php'
    );
    expect(new TidalDimension().compute(cpg.getNode('s')!, cpg)).toBe(0);
  });
  test('two close sinks = high risk', () => {
    const cpg = createCPG(
      new Map([
        ['s1', { id: 's1', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
        ['s2', { id: 's2', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
      ]),
      [{ source: 's1', target: 's2', kind: 'data' }], 'php'
    );
    expect(new TidalDimension().compute(cpg.getNode('s1')!, cpg)).toBeGreaterThan(0);
  });
  test('distant sinks = low risk', () => {
    const cpg = createCPG(
      new Map([
        ['s1', { id: 's1', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
        ['s2', { id: 's2', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: { is_sink: 1 } }],
        ['m1', { id: 'm1', type: 'stmt', file: 'a', line: 3, col: 0, code: '', language: 'php', features: {} }],
        ['m2', { id: 'm2', type: 'stmt', file: 'a', line: 4, col: 0, code: '', language: 'php', features: {} }],
        ['m3', { id: 'm3', type: 'stmt', file: 'a', line: 5, col: 0, code: '', language: 'php', features: {} }],
        ['m4', { id: 'm4', type: 'stmt', file: 'a', line: 6, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 's1', target: 'm1', kind: 'data' },
        { source: 'm1', target: 'm2', kind: 'data' },
        { source: 'm2', target: 'm3', kind: 'data' },
        { source: 'm3', target: 'm4', kind: 'data' },
        { source: 'm4', target: 's2', kind: 'data' },
      ], 'php'
    );
    expect(new TidalDimension().compute(cpg.getNode('s1')!, cpg)).toBe(0);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/tidal.ts theory/dimensions/tidal.md tests/unit/engine/dimensions/tidal.test.ts
git commit -m "feat(dimensions): 潮汐 (tidal) — vulnerability chain risk"
```

---

## Task 3: 相对论 (Relativistic) — P1

**Files:**
- Create: `src/engine/dimensions/relativistic.ts`
- Create: `theory/dimensions/relativistic.md`
- Test: `tests/unit/engine/dimensions/relativistic.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #7: 相对论修正 (Relativistic Correction)

**Cosmic-galaxy formula**: `G_μν + Λ·g_μν = κ·T_μν`
**Schwarzschild**: `r_s = 2·Γ·W_sink/c²`

**Code mapping**: Deep nesting = spacetime curvature
- Nesting depth > 5 = relativistic regime
- High cyclomatic complexity = mass

**security-vule implementation**:
- Read `nesting_depth` and `cyclomatic_complexity` features
- Risk = sigmoid of depth × complexity
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/relativistic.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class RelativisticDimension extends BaseDimension {
  readonly name = 'relativistic';
  readonly weight = 0.10;

  compute(node: CPGNode, _cpg: CPG): number {
    const depth = node.features['nesting_depth'] || 0;
    const cyclo = node.features['cyclomatic_complexity'] || 0;
    // Schwarzschild-like: depth > 5 = black hole risk
    const curvatureRisk = depth > 5 ? 1 - 1 / (depth - 4) : 0;
    const complexityRisk = Math.min(1, cyclo / 20);
    return Math.min(1, Math.max(curvatureRisk, complexityRisk));
  }
}
```

```typescript
// tests/unit/engine/dimensions/relativistic.test.ts
import { describe, expect, test } from 'bun:test';
import { RelativisticDimension } from '../../../../src/engine/dimensions/relativistic.js';

describe('RelativisticDimension', () => {
  test('weight is 0.10', () => expect(new RelativisticDimension().weight).toBe(0.10));
  test('shallow + simple = low risk', () => {
    expect(new RelativisticDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { nesting_depth: 2, cyclomatic_complexity: 1 } }, {} as any)).toBe(0);
  });
  test('deep nesting = high risk', () => {
    const v = new RelativisticDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { nesting_depth: 10 } }, {} as any);
    expect(v).toBeGreaterThan(0.5);
  });
  test('high cyclomatic = high risk', () => {
    const v = new RelativisticDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { cyclomatic_complexity: 25 } }, {} as any);
    expect(v).toBe(1);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/relativistic.ts theory/dimensions/relativistic.md tests/unit/engine/dimensions/relativistic.test.ts
git commit -m "feat(dimensions): 相对论 (relativistic) — nesting/complexity risk"
```

---

## Task 4: 暗物质 (Dark Matter) — P1

**Files:**
- Create: `src/engine/dimensions/dark-matter.ts`
- Create: `theory/dimensions/dark-matter.md`
- Test: `tests/unit/engine/dimensions/dark-matter.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #8: 暗物质/暗能量 (Dark Matter)

**Cosmic-galaxy formula**: `M_dark(v) = observed_gravity(v) − visible_gravity(v)`

**Code mapping**: Hidden dependencies (reflection, dynamic loading, DI, callbacks)
- These produce "observed" data flow that AST cannot trace
- Risk = count of dynamic constructs in file

**security-vule implementation**:
- Reads `dynamic_calls` feature (externally populated)
- Plus heuristic: features named `reflection`, `eval`, `include`
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/dark-matter.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

const DARK_PATTERNS = ['reflection', 'eval', 'include', 'require', 'dl', 'ffi', 'callback', 'listener'];

export class DarkMatterDimension extends BaseDimension {
  readonly name = 'darkMatter';
  readonly weight = 0.08;

  compute(node: CPGNode, _cpg: CPG): number {
    let count = node.features['dynamic_calls'] || 0;
    for (const p of DARK_PATTERNS) {
      if (node.features[p]) count += node.features[p];
    }
    return Math.min(1, count / 5);
  }
}
```

```typescript
// tests/unit/engine/dimensions/dark-matter.test.ts
import { describe, expect, test } from 'bun:test';
import { DarkMatterDimension } from '../../../../src/engine/dimensions/dark-matter.js';

describe('DarkMatterDimension', () => {
  test('weight is 0.08', () => expect(new DarkMatterDimension().weight).toBe(0.08));
  test('no dynamic = 0', () => {
    expect(new DarkMatterDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }, {} as any)).toBe(0);
  });
  test('5 dynamic calls = 1.0', () => {
    expect(new DarkMatterDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { dynamic_calls: 5 } }, {} as any)).toBe(1);
  });
  test('reflection feature counts', () => {
    const v = new DarkMatterDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { reflection: 3 } }, {} as any);
    expect(v).toBeGreaterThan(0.5);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/dark-matter.ts theory/dimensions/dark-matter.md tests/unit/engine/dimensions/dark-matter.test.ts
git commit -m "feat(dimensions): 暗物质 (dark-matter) — hidden dependencies"
```

---

## Task 5: 熵增 (Entropy) — P1

**Files:**
- Create: `src/engine/dimensions/entropy.ts`
- Create: `theory/dimensions/entropy.md`
- Test: `tests/unit/engine/dimensions/entropy.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #10: 熵增原理 (Entropy)

**Cosmic-galaxy formula**: `ρ_vuln(t) = ρ₀·exp(λ·S_code(t))`

**Code mapping**: Code entropy increases monotonically without maintenance
- Per-function Halstead volume or token diversity
- Risk = sigmoid(entropy - threshold)
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/entropy.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class EntropyDimension extends BaseDimension {
  readonly name = 'entropy';
  readonly weight = 0.05;

  compute(node: CPGNode, _cpg: CPG): number {
    const halstead = node.features['halstead_volume'] || 0;
    const tokenDiversity = node.features['token_diversity'] || 0;
    const signal = Math.max(halstead / 1000, tokenDiversity);
    return Math.min(1, signal);
  }
}
```

```typescript
// tests/unit/engine/dimensions/entropy.test.ts
import { describe, expect, test } from 'bun:test';
import { EntropyDimension } from '../../../../src/engine/dimensions/entropy.js';

describe('EntropyDimension', () => {
  test('weight is 0.05', () => expect(new EntropyDimension().weight).toBe(0.05));
  test('zero entropy = 0', () => {
    expect(new EntropyDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }, {} as any)).toBe(0);
  });
  test('high halstead = high risk', () => {
    const v = new EntropyDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { halstead_volume: 1500 } }, {} as any);
    expect(v).toBe(1);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/entropy.ts theory/dimensions/entropy.md tests/unit/engine/dimensions/entropy.test.ts
git commit -m "feat(dimensions): 熵增 (entropy) — code entropy risk"
```

---

## Task 6: 量子 (Quantum) — P2

**Files:**
- Create: `src/engine/dimensions/quantum.ts`
- Create: `theory/dimensions/quantum.md`
- Test: `tests/unit/engine/dimensions/quantum.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #9: 量子态 (Quantum State)

**Cosmic-galaxy formula**: `|ψ⟩ = α|safe⟩ + β|vuln⟩, |α|²+|β|²=1`

**Code mapping**: Race condition / TOCTOU / shared state
- `|ψ⟩` superposition of safe/vulnerable execution paths
- Probability |β|² from concurrent construct count
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/quantum.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class QuantumDimension extends BaseDimension {
  readonly name = 'quantum';
  readonly weight = 0.07;

  compute(node: CPGNode, _cpg: CPG): number {
    const concurrency = (node.features['shared_state'] || 0) +
      (node.features['async_await'] || 0) +
      (node.features['threads'] || 0);
    return Math.min(1, concurrency / 5);
  }
}
```

```typescript
// tests/unit/engine/dimensions/quantum.test.ts
import { describe, expect, test } from 'bun:test';
import { QuantumDimension } from '../../../../src/engine/dimensions/quantum.js';

describe('QuantumDimension', () => {
  test('weight is 0.07', () => expect(new QuantumDimension().weight).toBe(0.07));
  test('no concurrency = 0', () => {
    expect(new QuantumDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }, {} as any)).toBe(0);
  });
  test('5 concurrency features = 1', () => {
    expect(new QuantumDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { shared_state: 3, async_await: 2 } }, {} as any)).toBe(1);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/quantum.ts theory/dimensions/quantum.md tests/unit/engine/dimensions/quantum.test.ts
git commit -m "feat(dimensions): 量子 (quantum) — race condition risk"
```

---

## Task 7: 拓扑 (Topology) — P2

**Files:**
- Create: `src/engine/dimensions/topology.ts`
- Create: `theory/dimensions/topology.md`
- Test: `tests/unit/engine/dimensions/topology.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #12: 拓扑 (Topology)

**Cosmic-galaxy formula**: `β₀/β₁/β₂` (Betti numbers)

**Code mapping**:
- β₀ = connected components (modularity)
- β₁ = cycles (loop dependencies / infinite recursion)
- β₂ = cavities (missing abstraction layers)

**security-vule implementation**:
- Cycle count via DFS (β₁ proxy)
- Risk = sigmoid(cycle_count)
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/topology.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TopologyDimension extends BaseDimension {
  readonly name = 'topology';
  readonly weight = 0.05;

  compute(node: CPGNode, cpg: CPG): number {
    // Approximate: count back-edges reachable from node (β₁ proxy)
    let cycles = 0;
    const visited = new Set<string>();
    const stack: Array<{ node: string; ancestors: Set<string> }> = [
      { node: node.id, ancestors: new Set() },
    ];
    while (stack.length) {
      const { node: cur, ancestors } = stack.pop()!;
      if (visited.has(cur)) { cycles++; continue; }
      visited.add(cur);
      const newAncestors = new Set([...ancestors, cur]);
      for (const e of cpg.outEdges(cur)) {
        if (newAncestors.has(e.target)) cycles++;
        else stack.push({ node: e.target, ancestors: newAncestors });
      }
    }
    return Math.min(1, cycles / 3);
  }
}
```

```typescript
// tests/unit/engine/dimensions/topology.test.ts
import { describe, expect, test } from 'bun:test';
import { TopologyDimension } from '../../../../src/engine/dimensions/topology.js';
import { createCPG } from '../../../../src/engine/cpg/types.js';

describe('TopologyDimension', () => {
  test('weight is 0.05', () => expect(new TopologyDimension().weight).toBe(0.05));
  test('acyclic graph = 0', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [{ source: 'a', target: 'b', kind: 'data' }], 'php'
    );
    expect(new TopologyDimension().compute(cpg.getNode('a')!, cpg)).toBe(0);
  });
  test('cyclic graph (a→b→a) = high risk', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'php', features: {} }],
      ]),
      [
        { source: 'a', target: 'b', kind: 'data' },
        { source: 'b', target: 'a', kind: 'data' },
      ], 'php'
    );
    expect(new TopologyDimension().compute(cpg.getNode('a')!, cpg)).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/topology.ts theory/dimensions/topology.md tests/unit/engine/dimensions/topology.test.ts
git commit -m "feat(dimensions): 拓扑 (topology) — cycle detection"
```

---

## Task 8: 信息论 (Information) — P2

**Files:**
- Create: `src/engine/dimensions/information.ts`
- Create: `theory/dimensions/information.md`
- Test: `tests/unit/engine/dimensions/information.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension #17: 信息论 (Information Theory)

**Cosmic-galaxy formula**: `H = −Σ p log p` (Shannon entropy)

**Code mapping**: Token-level entropy
- Low entropy = repetitive code (often auto-generated)
- High entropy = random/unpredictable code (often obfuscated)
- Optimal: 3.5-5.5 bits/token (per cosmic-galaxy)

**security-vule implementation**:
- Reads `token_entropy` feature (externally computed)
- Risk = sigmoid(|entropy - 4.5|) — too high or too low is risky
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/information.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

const OPTIMAL = 4.5;
const RANGE = 1.0;

export class InformationDimension extends BaseDimension {
  readonly name = 'information';
  readonly weight = 0.04;

  compute(node: CPGNode, _cpg: CPG): number {
    const h = node.features['token_entropy'];
    if (h === undefined) return 0;
    const deviation = Math.abs(h - OPTIMAL) / RANGE;
    return Math.min(1, deviation);
  }
}
```

```typescript
// tests/unit/engine/dimensions/information.test.ts
import { describe, expect, test } from 'bun:test';
import { InformationDimension } from '../../../../src/engine/dimensions/information.js';

describe('InformationDimension', () => {
  test('weight is 0.04', () => expect(new InformationDimension().weight).toBe(0.04));
  test('undefined entropy = 0', () => {
    expect(new InformationDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: {} }, {} as any)).toBe(0);
  });
  test('optimal entropy (4.5) = 0 risk', () => {
    expect(new InformationDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { token_entropy: 4.5 } }, {} as any)).toBe(0);
  });
  test('extreme entropy (7.5) = 1 risk', () => {
    expect(new InformationDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'php', features: { token_entropy: 7.5 } }, {} as any)).toBe(1);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/information.ts theory/dimensions/information.md tests/unit/engine/dimensions/information.test.ts
git commit -m "feat(dimensions): 信息论 (information) — Shannon entropy"
```

---

## Task 9: Register All P1+P2 + Integration Test

**Files:**
- Modify: `src/engine/dimensions/registry.ts`
- Create: `tests/unit/engine/dimensions/p1p2-integration.test.ts`

- [ ] **Step 1: Update registry**

```typescript
// src/engine/dimensions/registry.ts (extend DIMENSIONS)
import { GravityDimension } from './gravity.js';
import { KeplerDimension } from './kepler.js';
import { OrbitalDimension } from './orbital.js';
import { NBodyDimension } from './nbody.js';
import { PerturbationDimension } from './perturbation.js';
import { TidalDimension } from './tidal.js';
import { RelativisticDimension } from './relativistic.js';
import { DarkMatterDimension } from './dark-matter.js';
import { EntropyDimension } from './entropy.js';
import { QuantumDimension } from './quantum.js';
import { TopologyDimension } from './topology.js';
import { InformationDimension } from './information.js';

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
  perturbation: new PerturbationDimension(),
  tidal: new TidalDimension(),
  relativistic: new RelativisticDimension(),
  darkMatter: new DarkMatterDimension(),
  entropy: new EntropyDimension(),
  quantum: new QuantumDimension(),
  topology: new TopologyDimension(),
  information: new InformationDimension(),
};
```

- [ ] **Step 2: Integration test**

```typescript
// tests/unit/engine/dimensions/p1p2-integration.test.ts
import { describe, expect, test } from 'bun:test';
import { DIMENSIONS, normalizeWeights } from '../../../../src/engine/dimensions/registry.js';

describe('P1+P2 dimensions integration', () => {
  test('all 8 new dimensions registered', () => {
    for (const name of ['perturbation', 'tidal', 'relativistic', 'darkMatter', 'entropy', 'quantum', 'topology', 'information']) {
      expect(DIMENSIONS[name]).toBeDefined();
    }
  });
  test('total of all weights normalizes to 1.0', () => {
    const raw: Record<string, number> = {};
    for (const [k, d] of Object.entries(DIMENSIONS)) raw[k] = d.weight;
    const norm = normalizeWeights(raw);
    const sum = Object.values(norm).reduce((s, w) => s + w, 0);
    expect(Math.abs(sum - 1.0)).toBeLessThan(0.01);
  });
  test('total dimensions count = 13', () => {
    expect(Object.keys(DIMENSIONS).length).toBe(13);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/registry.ts tests/unit/engine/dimensions/p1p2-integration.test.ts
git commit -m "feat(dimensions): register P1+P2 dimensions (total 13)"
```

---

## Task 10: Run All Sprint 4 Tests

- [ ] **Step 1: Run all tests**

Run: `bun test tests/unit/engine/dimensions/`
Expected: ~30 tests PASS

- [ ] **Step 2: Type check**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head`

- [ ] **Step 3: Final commit if needed**

---

## Definition of Done (Sprint 4)

- [ ] 5 P1 dimensions (perturbation, tidal, relativistic, darkMatter, entropy)
- [ ] 3 P2 dimensions (quantum, topology, information)
- [ ] All registered in `DIMENSIONS` (total 13)
- [ ] 8 theory markdown docs
- [ ] 30 tests passing
- [ ] 0 new TypeScript errors

**Next sprint**: Sprint 5 — CLI commands (`vule analyze`, `vule dimension`, `vule visualize`) + Web UI (`vule server`) + interactive HTML reports.