# Sprint 6: Math Frameworks Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 6 additional math-framework dimensions beyond cosmic-galaxy's 23: 类型论 (type theory), 范畴论/数据流函子 (category/data-flow functor), 拓扑数据分析 TDA (persistent homology), 纯函数式 (pure functional), 抽象解释 (abstract interpretation), 符号执行 (symbolic execution). Each is a P3 (reduced-depth) detector.

**Architecture:** Same `BaseDimension` pattern. P3 detectors may read external features (TDA requires Ripser integration; symbolic execution requires Z3 optional). Documented in `theory/dimensions/` with explicit depth notes.

**Spec reference:** §3.2 (additional 6 frameworks).

**Depends on:** Sprint 1-5.

---

## File Structure

| File | Responsibility | Lines |
|------|---------------|-------|
| `src/engine/dimensions/type-theory.ts` | E1: Type safety checker | ~80 |
| `src/engine/dimensions/functor.ts` | E2: Data-flow functor | ~80 |
| `src/engine/dimensions/tda.ts` | E3: Persistent homology (Betti numbers) | ~120 |
| `src/engine/dimensions/pure-functional.ts` | E4: Immutability / side-effect detector | ~80 |
| `src/engine/dimensions/abstract-interpret.ts` | E5: Abstract value range analysis | ~100 |
| `src/engine/dimensions/symbolic-exec.ts` | E6: Symbolic path conditions | ~100 |
| `theory/dimensions/{name}.md` (6 files) | Theory docs | ~240 |
| `tests/unit/engine/dimensions/{name}.test.ts` (6 files) | Tests | ~480 |

**Total**: ~18 files, ~1280 lines.

---

## Task 1: 类型论 (Type Theory)

**Files:**
- Create: `src/engine/dimensions/type-theory.ts`
- Create: `theory/dimensions/type-theory.md`
- Test: `tests/unit/engine/dimensions/type-theory.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension E1: 类型论 (Type Theory)

**Framework**: Dependent types + linear types → security guarantees

**Code mapping**: TypeScript strict mode violations
- `any` usage = unsafe escape hatch
- Missing type annotations = unverifiable contract
- `as` casts = trust assertions

**security-vule implementation**:
- Read `any_count`, `untyped_count`, `cast_count` features
- Risk = (any × 2 + untyped + cast) / total_loc
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/type-theory.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TypeTheoryDimension extends BaseDimension {
  readonly name = 'typeTheory';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const any = node.features['any_count'] || 0;
    const untyped = node.features['untyped_count'] || 0;
    const cast = node.features['cast_count'] || 0;
    const loc = Math.max(1, node.features['loc'] || 1);
    const raw = (any * 2 + untyped + cast) / loc;
    return Math.min(1, raw);
  }
}
```

```typescript
// tests/unit/engine/dimensions/type-theory.test.ts
import { describe, expect, test } from 'bun:test';
import { TypeTheoryDimension } from '../../../../src/engine/dimensions/type-theory.js';

describe('TypeTheoryDimension', () => {
  test('weight is 0.03', () => expect(new TypeTheoryDimension().weight).toBe(0.03));
  test('zero violations = 0 risk', () => {
    expect(new TypeTheoryDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }, {} as any)).toBe(0);
  });
  test('many `any` = high risk', () => {
    const v = new TypeTheoryDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: { any_count: 5, loc: 10 } }, {} as any);
    expect(v).toBe(1);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/type-theory.ts theory/dimensions/type-theory.md tests/unit/engine/dimensions/type-theory.test.ts
git commit -m "feat(dimensions): 类型论 (type-theory) — TS strict mode violations"
```

---

## Task 2: 范畴论/数据流函子 (Functor)

**Files:**
- Create: `src/engine/dimensions/functor.ts`
- Create: `theory/dimensions/functor.md`
- Test: `tests/unit/engine/dimensions/functor.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension E2: 范畴论/数据流函子 (Category Theory — Data-Flow Functor)

**Framework**: Functor F: Code → Security preserves structure

**Code mapping**: Data-flow homomorphism check
- A functor maps source AST/data structures to security verdicts
- A "natural transformation" between two analyses = consistent findings

**security-vule implementation**:
- Reads two consensus results (from different LLMs)
- Risk = disagreement between them (proxy for functor violation)
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/functor.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class FunctorDimension extends BaseDimension {
  readonly name = 'functor';
  readonly weight = 0.03;
  private verdicts: Map<string, [number, number]> = new Map();

  setVerdicts(map: Record<string, [number, number]>): void {
    this.verdicts = new Map(Object.entries(map));
  }

  compute(node: CPGNode, _cpg: CPG): number {
    const pair = this.verdicts.get(node.id);
    if (!pair) return 0;
    return Math.abs(pair[0] - pair[1]);
  }
}
```

```typescript
// tests/unit/engine/dimensions/functor.test.ts
import { describe, expect, test } from 'bun:test';
import { FunctorDimension } from '../../../../src/engine/dimensions/functor.js';

describe('FunctorDimension', () => {
  test('weight is 0.03', () => expect(new FunctorDimension().weight).toBe(0.03));
  test('no verdicts = 0', () => {
    expect(new FunctorDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }, {} as any)).toBe(0);
  });
  test('matching verdicts = 0', () => {
    const d = new FunctorDimension();
    d.setVerdicts({ x: [0.5, 0.5] });
    expect(d.compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }, {} as any)).toBe(0);
  });
  test('mismatched verdicts = high risk', () => {
    const d = new FunctorDimension();
    d.setVerdicts({ x: [0.1, 0.9] });
    expect(d.compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }, {} as any)).toBeCloseTo(0.8);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/functor.ts theory/dimensions/functor.md tests/unit/engine/dimensions/functor.test.ts
git commit -m "feat(dimensions): 范畴论 (functor) — cross-analysis disagreement"
```

---

## Task 3: 拓扑数据分析 (TDA)

**Files:**
- Create: `src/engine/dimensions/tda.ts`
- Create: `theory/dimensions/tda.md`
- Test: `tests/unit/engine/dimensions/tda.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension E3: 拓扑数据分析 (Topological Data Analysis)

**Framework**: Persistent homology → Betti numbers β₀/β₁/β₂

**Code mapping**:
- β₀ = number of connected components (modularity)
- β₁ = cycles (circular dependencies)
- β₂ = cavities (missing abstraction layers)

**security-vule implementation**:
- Compute β₀/β₁ via BFS + DFS (no Ripser needed for graph CPG)
- β₀ = components; β₁ = edges - nodes + components (Euler formula)
- Risk = sigmoid(β₁ - threshold)
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/tda.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class TdaDimension extends BaseDimension {
  readonly name = 'tda';
  readonly weight = 0.03;

  compute(node: CPGNode, cpg: CPG): number {
    // β₀ via BFS from node
    const visited = new Set<string>();
    const queue = [node.id];
    while (queue.length) {
      const cur = queue.shift()!;
      if (visited.has(cur)) continue;
      visited.add(cur);
      for (const e of cpg.outEdges(cur)) queue.push(e.target);
      for (const e of cpg.inEdges(cur)) queue.push(e.source);
    }
    const beta0 = visited.size;
    // β₁ via Euler: nodes - edges + components - β₁ = 1 for connected
    const totalNodes = cpg.nodes.size;
    const totalEdges = cpg.edges.length;
    const beta1 = totalNodes - totalEdges + 1; // simplified
    return Math.min(1, beta1 / 5);
  }
}
```

```typescript
// tests/unit/engine/dimensions/tda.test.ts
import { describe, expect, test } from 'bun:test';
import { TdaDimension } from '../../../../src/engine/dimensions/tda.js';
import { createCPG } from '../../../../src/engine/cpg/types.js';

describe('TdaDimension', () => {
  test('weight is 0.03', () => expect(new TdaDimension().weight).toBe(0.03));
  test('acyclic graph = 0', () => {
    const cpg = createCPG(
      new Map([
        ['a', { id: 'a', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }],
        ['b', { id: 'b', type: 'stmt', file: 'a', line: 2, col: 0, code: '', language: 'typescript', features: {} }],
      ]),
      [{ source: 'a', target: 'b', kind: 'data' }], 'typescript'
    );
    expect(new TdaDimension().compute(cpg.getNode('a')!, cpg)).toBe(0);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/tda.ts theory/dimensions/tda.md tests/unit/engine/dimensions/tda.test.ts
git commit -m "feat(dimensions): TDA — Betti numbers risk"
```

---

## Task 4: 纯函数式 (Pure Functional)

**Files:**
- Create: `src/engine/dimensions/pure-functional.ts`
- Create: `theory/dimensions/pure-functional.md`
- Test: `tests/unit/engine/dimensions/pure-functional.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension E4: 纯函数式安全 (Pure Functional Security)

**Framework**: Immutability + side-effect isolation → easier reasoning

**Code mapping**:
- `let` / `var` mutability = state risk
- Side-effect calls (I/O, network) in non-pure context = isolation failure
- Pure functions have no risk

**security-vule implementation**:
- Read `mutable_vars`, `side_effects` features
- Risk = (mutable × 0.5 + side_effects) / total
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/pure-functional.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class PureFunctionalDimension extends BaseDimension {
  readonly name = 'pureFunctional';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const mut = node.features['mutable_vars'] || 0;
    const effects = node.features['side_effects'] || 0;
    const total = Math.max(1, node.features['loc'] || 1);
    return Math.min(1, (mut * 0.5 + effects) / total);
  }
}
```

```typescript
// tests/unit/engine/dimensions/pure-functional.test.ts
import { describe, expect, test } from 'bun:test';
import { PureFunctionalDimension } from '../../../../src/engine/dimensions/pure-functional.js';

describe('PureFunctionalDimension', () => {
  test('weight is 0.03', () => expect(new PureFunctionalDimension().weight).toBe(0.03));
  test('pure function = 0', () => {
    expect(new PureFunctionalDimension().compute({ id: 'x', type: 'func', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: { loc: 10 } }, {} as any)).toBe(0);
  });
  test('impure function = high risk', () => {
    const v = new PureFunctionalDimension().compute({ id: 'x', type: 'func', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: { mutable_vars: 5, side_effects: 3, loc: 10 } }, {} as any);
    expect(v).toBeGreaterThan(0.3);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/pure-functional.ts theory/dimensions/pure-functional.md tests/unit/engine/dimensions/pure-functional.test.ts
git commit -m "feat(dimensions): 纯函数式 (pure-functional) — mutation/side-effect"
```

---

## Task 5: 抽象解释 (Abstract Interpretation)

**Files:**
- Create: `src/engine/dimensions/abstract-interpret.ts`
- Create: `theory/dimensions/abstract-interpret.md`
- Test: `tests/unit/engine/dimensions/abstract-interpret.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension E5: 抽象解释 (Abstract Interpretation)

**Framework**: Cousot & Cousot 1977 — sound approximation of program semantics

**Code mapping**: Static value-range analysis
- Interval analysis: `[min, max]` for numeric vars
- String length analysis: `[min_len, max_len]` for string vars
- Taint domain: {clean, dirty}

**security-vule implementation**:
- Read precomputed `taint_range` (min/max taint value)
- Read `value_range` (numeric min/max)
- Risk = probability of dangerous value given range
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/abstract-interpret.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class AbstractInterpretDimension extends BaseDimension {
  readonly name = 'abstractInterpret';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const taintMax = node.features['taint_max'] || 0;
    const valueRange = node.features['value_range'] || 0;
    return Math.min(1, (taintMax + valueRange) / 10);
  }
}
```

```typescript
// tests/unit/engine/dimensions/abstract-interpret.test.ts
import { describe, expect, test } from 'bun:test';
import { AbstractInterpretDimension } from '../../../../src/engine/dimensions/abstract-interpret.js';

describe('AbstractInterpretDimension', () => {
  test('weight is 0.03', () => expect(new AbstractInterpretDimension().weight).toBe(0.03));
  test('no ranges = 0', () => {
    expect(new AbstractInterpretDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }, {} as any)).toBe(0);
  });
  test('large ranges = high risk', () => {
    const v = new AbstractInterpretDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: { taint_max: 5, value_range: 5 } }, {} as any);
    expect(v).toBe(1);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/abstract-interpret.ts theory/dimensions/abstract-interpret.md tests/unit/engine/dimensions/abstract-interpret.test.ts
git commit -m "feat(dimensions): 抽象解释 (abstract-interpret) — value range risk"
```

---

## Task 6: 符号执行 (Symbolic Execution)

**Files:**
- Create: `src/engine/dimensions/symbolic-exec.ts`
- Create: `theory/dimensions/symbolic-exec.md`
- Test: `tests/unit/engine/dimensions/symbolic-exec.test.ts`

- [ ] **Step 1: Theory doc**

```markdown
# Dimension E6: 符号执行 (Symbolic Execution)

**Framework**: Execute programs with symbolic inputs (King 1976)

**Code mapping**: Path constraint analysis
- Each `if` doubles paths → exponential growth
- Solver-checked constraints expose unreachable / always-true paths

**security-vule implementation**:
- Read `path_count`, `solver_violations` features (precomputed by Z3 or similar)
- Risk = sigmoid(solver_violations)
- Optional: lazy import of `z3-solver` if available
```

- [ ] **Step 2: Implementation + test**

```typescript
// src/engine/dimensions/symbolic-exec.ts
import { BaseDimension } from './base.js';
import type { CPG, CPGNode } from '../cpg/types.js';

export class SymbolicExecDimension extends BaseDimension {
  readonly name = 'symbolicExec';
  readonly weight = 0.03;

  compute(node: CPGNode, _cpg: CPG): number {
    const paths = node.features['path_count'] || 0;
    const violations = node.features['solver_violations'] || 0;
    return Math.min(1, (violations * 2 + Math.log2(Math.max(1, paths))) / 10);
  }
}
```

```typescript
// tests/unit/engine/dimensions/symbolic-exec.test.ts
import { describe, expect, test } from 'bun:test';
import { SymbolicExecDimension } from '../../../../src/engine/dimensions/symbolic-exec.js';

describe('SymbolicExecDimension', () => {
  test('weight is 0.03', () => expect(new SymbolicExecDimension().weight).toBe(0.03));
  test('no info = 0', () => {
    expect(new SymbolicExecDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: {} }, {} as any)).toBe(0);
  });
  test('many paths + violations = high risk', () => {
    const v = new SymbolicExecDimension().compute({ id: 'x', type: 'stmt', file: 'a', line: 1, col: 0, code: '', language: 'typescript', features: { path_count: 1024, solver_violations: 3 } }, {} as any);
    expect(v).toBeGreaterThan(0.5);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/symbolic-exec.ts theory/dimensions/symbolic-exec.md tests/unit/engine/dimensions/symbolic-exec.test.ts
git commit -m "feat(dimensions): 符号执行 (symbolic-exec) — path constraints risk"
```

---

## Task 7: Register All Frameworks + Integration Test

**Files:**
- Modify: `src/engine/dimensions/registry.ts`
- Create: `tests/unit/engine/dimensions/frameworks-integration.test.ts`

- [ ] **Step 1: Update registry**

Add to `src/engine/dimensions/registry.ts`:

```typescript
import { TypeTheoryDimension } from './type-theory.js';
import { FunctorDimension } from './functor.js';
import { TdaDimension } from './tda.js';
import { PureFunctionalDimension } from './pure-functional.js';
import { AbstractInterpretDimension } from './abstract-interpret.js';
import { SymbolicExecDimension } from './symbolic-exec.js';

// In DIMENSIONS object, add:
  typeTheory: new TypeTheoryDimension(),
  functor: new FunctorDimension(),
  tda: new TdaDimension(),
  pureFunctional: new PureFunctionalDimension(),
  abstractInterpret: new AbstractInterpretDimension(),
  symbolicExec: new SymbolicExecDimension(),
```

- [ ] **Step 2: Integration test**

```typescript
// tests/unit/engine/dimensions/frameworks-integration.test.ts
import { describe, expect, test } from 'bun:test';
import { DIMENSIONS } from '../../../../src/engine/dimensions/registry.js';

describe('Math frameworks integration', () => {
  test('all 6 frameworks registered', () => {
    for (const n of ['typeTheory', 'functor', 'tda', 'pureFunctional', 'abstractInterpret', 'symbolicExec']) {
      expect(DIMENSIONS[n]).toBeDefined();
    }
  });
  test('total dimensions = 19 (13 cosmic + 6 frameworks)', () => {
    expect(Object.keys(DIMENSIONS).length).toBe(19);
  });
});
```

- [ ] **Step 3: Run → expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/engine/dimensions/registry.ts tests/unit/engine/dimensions/frameworks-integration.test.ts
git commit -m "feat(dimensions): register 6 math frameworks (total 19)"
```

---

## Task 8: Run All Sprint 6 Tests

- [ ] **Step 1: Run all tests**

Run: `bun test tests/unit/engine/dimensions/`
Expected: ~50 tests PASS

- [ ] **Step 2: Type check**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head`

- [ ] **Step 3: Final commit**

---

## Definition of Done (Sprint 6)

- [ ] 6 math framework dimensions implemented (P3 depth)
- [ ] 19 total dimensions registered
- [ ] 6 theory docs
- [ ] 18+ tests passing
- [ ] 0 new TypeScript errors

**Next sprint**: Sprint 7 — cosmic-galaxy equivalence test (cross-project integration test).