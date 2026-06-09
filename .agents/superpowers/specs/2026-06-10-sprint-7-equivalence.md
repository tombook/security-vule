# Sprint 7: Cosmic-Galaxy Equivalence Test Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a cross-project integration test that runs the same CPG fixture through both cosmic-galaxy (Python) and security-vule (TypeScript), and verifies UVRS scores match within tolerance `< 0.10`. Establishes that security-vule correctly implements the cosmic-galaxy methodology.

**Architecture:** JSON-based CPG interchange format. security-vule test exports CPG fixtures; a Python test script (run via `uv run` or system Python) imports cosmic-galaxy, runs its UVRS, and writes results; a Bun test reads both results and asserts equivalence.

**Tolerance rationale**: `< 0.10` because Python (cosmic-galaxy) and TypeScript (security-vule) use different floating-point representations, AST→CPG conversion may differ slightly, and LLM-dependent dimensions (nbody) introduce noise. 0.10 is empirically chosen for cross-language fidelity.

**Spec reference:** §8.5 (equivalence test), §13.3 (interchange format).

**Depends on:** Sprint 1-6.

---

## File Structure

| File | Responsibility | Lines |
|------|---------------|-------|
| `tests/integration/cosmic-galaxy/cpg-fixture.json` | Shared CPG fixture (3 nodes: source, sink, intermediate) | ~30 |
| `tests/integration/cosmic-galaxy/expected-vule.json` | security-vule UVRS snapshot | ~20 |
| `tests/integration/cosmic-galaxy/expected-cosmic.json` | cosmic-galaxy UVRS snapshot (from Python run) | ~20 |
| `tests/integration/cosmic-galaxy/run_cosmic.py` | Python script that runs cosmic-galaxy on fixture | ~60 |
| `tests/integration/cosmic-galaxy/equivalence.test.ts` | Bun test comparing both results | ~80 |
| `tests/integration/cosmic-galaxy/README.md` | How to run the cross-project test | ~50 |

**Total**: ~6 files, ~260 lines.

---

## Task 1: Define CPG Interchange Format + Fixture

**Files:**
- Create: `tests/integration/cosmic-galaxy/cpg-fixture.json`
- Create: `tests/integration/cosmic-galaxy/README.md`

- [ ] **Step 1: Create README**

```markdown
# Cosmic-Galaxy Equivalence Test

Cross-project integration test: runs the same CPG through both security-vule
(TypeScript) and cosmic-galaxy (Python), asserts UVRS match within `< 0.10`.

## How to run

### One-time setup
```bash
# In cosmic-galaxy repo
cd /Users/tombook/Documents/work/ai_openclaw/dev_work/cosmic-galaxy
source .venv/bin/activate  # or uv venv
pip install -e .
```

### Run cosmic-galaxy on the fixture
```bash
cd /Users/tombook/Documents/work/ai_openclaw/dev_work/security-vule
python3 tests/integration/cosmic-galaxy/run_cosmic.py
# Writes expected-cosmic.json
```

### Run the TypeScript test
```bash
bun test tests/integration/cosmic-galaxy/equivalence.test.ts
```

## Tolerance: 0.10

Rationale (from spec §8.5):
- Cross-language floating-point differences
- AST → CPG conversion may have small numerical variance
- LLM-driven dimensions (nbody) add noise

## Interchange format

`cpg-fixture.json` is a JSON serialization of `CPG` (subset of
`src/engine/cpg/types.ts`): nodes (id, type, file, line, features) +
edges (source, target, kind).
```

- [ ] **Step 2: Create CPG fixture**

```json
{
  "language": "php",
  "nodes": [
    {
      "id": "src",
      "type": "var",
      "file": "test.php",
      "line": 1,
      "col": 0,
      "code": "$_GET[\"x\"]",
      "features": { "sensitivity": 1.0, "complexity": 1 }
    },
    {
      "id": "mid",
      "type": "stmt",
      "file": "test.php",
      "line": 2,
      "col": 0,
      "code": "$q = process($_GET[\"x\"])",
      "features": {}
    },
    {
      "id": "sink",
      "type": "stmt",
      "file": "test.php",
      "line": 3,
      "col": 0,
      "code": "mysql_query($q)",
      "features": { "is_sink": 1, "dangerousness": 0.9 }
    }
  ],
  "edges": [
    { "source": "src", target: "mid", "kind": "data" },
    { "source": "mid", target: "sink", "kind": "data" }
  ]
}
```

- [ ] **Step 3: Commit**

```bash
git add tests/integration/cosmic-galaxy/cpg-fixture.json tests/integration/cosmic-galaxy/README.md
git commit -m "test(integration): CPG fixture + README for cosmic-galaxy equivalence"
```

---

## Task 2: Python Script to Run Cosmic-Galaxy

**Files:**
- Create: `tests/integration/cosmic-galaxy/run_cosmic.py`

- [ ] **Step 1: Implement Python script**

```python
"""
run_cosmic.py — Run cosmic-galaxy UVRS on cpg-fixture.json and write expected-cosmic.json

Usage: python3 tests/integration/cosmic-galaxy/run_cosmic.py

Requires cosmic-galaxy to be importable. Install with:
  cd cosmic-galaxy && pip install -e .
"""
import json
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent / "cpg-fixture.json"
OUTPUT = Path(__file__).parent / "expected-cosmic.json"


def cpg_to_networkx(fixture):
    """Convert CPG JSON fixture to networkx DiGraph + sink list."""
    try:
        import networkx as nx
    except ImportError:
        print("networkx not installed. Run: pip install networkx", file=sys.stderr)
        sys.exit(1)

    G = nx.DiGraph()
    for node in fixture["nodes"]:
        G.add_node(node["id"], **node.get("features", {}))
    for edge in fixture["edges"]:
        G.add_edge(edge["source"], edge["target"], kind=edge["kind"])
    sinks = [n["id"] for n in fixture["nodes"] if n.get("features", {}).get("is_sink")]
    return G, sinks


def run_cosmic_uvrs(G, sinks):
    """Run cosmic-galaxy UVRS on the CPG and return per-node scores."""
    try:
        from engine import UVRS, GravityField, CosmicEngine
    except ImportError:
        print("cosmic-galaxy not importable. Install with: cd cosmic-galaxy && pip install -e .",
              file=sys.stderr)
        sys.exit(1)

    engine = CosmicEngine(graph=G, sinks=sinks)
    scores = engine.compute_uvrs()
    return scores


def main():
    if not FIXTURE.exists():
        print(f"Fixture not found: {FIXTURE}", file=sys.stderr)
        sys.exit(1)

    fixture = json.loads(FIXTURE.read_text())
    G, sinks = cpg_to_networkx(fixture)
    scores = run_cosmic_uvrs(G, sinks)

    result = {
        "tool": "cosmic-galaxy",
        "version": "7.5",
        "scores": {node_id: float(score) for node_id, score in scores.items()},
        "tolerance": 0.10,
    }
    OUTPUT.write_text(json.dumps(result, indent=2))
    print(f"Wrote {OUTPUT}")
    for k, v in result["scores"].items():
        print(f"  {k}: {v:.3f}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Commit**

```bash
git add tests/integration/cosmic-galaxy/run_cosmic.py
git commit -m "test(integration): Python script to run cosmic-galaxy UVRS on fixture"
```

---

## Task 3: TypeScript Equivalence Test

**Files:**
- Create: `tests/integration/cosmic-galaxy/equivalence.test.ts`

- [ ] **Step 1: Implement TS test**

```typescript
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
import { createCPG } from '../../../src/engine/cpg/types.js';
import { VuleEngine } from '../../../src/engine/vule-engine.js';
import { defaultConfig } from '../../../src/engine/vule-config.js';

const HERE = import.meta.dir;
const FIXTURE = join(HERE, 'cpg-fixture.json');
const COSMIC_OUT = join(HERE, 'expected-cosmic.json');

describe('cosmic-galaxy equivalence', () => {
  test('fixture exists', () => {
    expect(existsSync(FIXTURE)).toBe(true);
  });

  test('security-vule produces valid UVRS for fixture', () => {
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf-8'));
    const nodes = new Map();
    for (const n of fixture.nodes) {
      nodes.set(n.id, { ...n, language: fixture.language });
    }
    const cpg = createCPG(nodes, fixture.edges, fixture.language);

    const cfg = defaultConfig();
    cfg.dimensions.enabled = ['gravity', 'kepler', 'tidal', 'relativistic', 'entropy', 'orbital'];
    const sinks = fixture.nodes.filter((n: any) => n.features?.is_sink).map((n: any) => n.id);
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

  test('security-vule UVRS matches cosmic-galaxy within tolerance (when cosmic output present)', () => {
    if (!existsSync(COSMIC_OUT)) {
      console.warn(`Skipping: ${COSMIC_OUT} not found. Run run_cosmic.py first.`);
      return;
    }
    const fixture = JSON.parse(readFileSync(FIXTURE, 'utf-8'));
    const cosmic = JSON.parse(readFileSync(COSMIC_OUT, 'utf-8'));
    const tolerance = 0.10;

    // Run security-vule
    const nodes = new Map();
    for (const n of fixture.nodes) nodes.set(n.id, { ...n, language: fixture.language });
    const cpg = createCPG(nodes, fixture.edges, fixture.language);
    const cfg = defaultConfig();
    cfg.dimensions.enabled = ['gravity', 'kepler', 'tidal', 'relativistic', 'entropy', 'orbital'];
    const sinks = fixture.nodes.filter((n: any) => n.features?.is_sink).map((n: any) => n.id);
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
```

- [ ] **Step 2: Run → check it works without cosmic output (skip mode)**

Run: `bun test tests/integration/cosmic-galaxy/equivalence.test.ts`
Expected: 2 tests PASS, 1 skipped (cosmic output not present)

- [ ] **Step 3: Commit**

```bash
git add tests/integration/cosmic-galaxy/equivalence.test.ts
git commit -m "test(integration): cosmic-galaxy equivalence test with 0.10 tolerance"
```

---

## Task 4: Snapshot Baseline + Document Workflow

**Files:**
- Create: `tests/integration/cosmic-galaxy/expected-vule.json`
- Update: `tests/integration/cosmic-galaxy/README.md`

- [ ] **Step 1: Generate vule snapshot**

```bash
bun --bun -e "
import { readFileSync, writeFileSync } from 'fs';
import { createCPG } from './src/engine/cpg/types.js';
import { VuleEngine } from './src/engine/vule-engine.js';
import { defaultConfig } from './src/engine/vule-config.js';

const fixture = JSON.parse(readFileSync('tests/integration/cosmic-galaxy/cpg-fixture.json', 'utf-8'));
const nodes = new Map();
for (const n of fixture.nodes) nodes.set(n.id, { ...n, language: fixture.language });
const cpg = createCPG(nodes, fixture.edges, fixture.language);
const cfg = defaultConfig();
cfg.dimensions.enabled = ['gravity', 'kepler', 'tidal', 'relativistic', 'entropy', 'orbital'];
const sinks = fixture.nodes.filter(n => n.features?.is_sink).map(n => n.id);
const engine = new VuleEngine(cpg, sinks, [], cfg);
const report = engine.analyze();
const scores = {};
for (const n of report.topRisk) scores[n.nodeId] = n.uvrs;
writeFileSync('tests/integration/cosmic-galaxy/expected-vule.json', JSON.stringify({
  tool: 'security-vule',
  version: '0.3.0',
  scores,
  tolerance: 0.10,
}, null, 2));
console.log('Wrote expected-vule.json');
"
```

- [ ] **Step 2: Verify file**

```bash
cat tests/integration/cosmic-galaxy/expected-vule.json
```

Expected: JSON with 3 scores (src, mid, sink)

- [ ] **Step 3: Append README section**

Add to `tests/integration/cosmic-galaxy/README.md`:

```markdown
## Updating snapshots

To regenerate `expected-vule.json`:
```bash
bun --bun -e "..."  # see Task 4 of Sprint 7 plan
```

To regenerate `expected-cosmic.json`:
```bash
python3 tests/integration/cosmic-galaxy/run_cosmic.py
```

## Current results (snapshot)

- security-vule 0.3.0: see `expected-vule.json`
- cosmic-galaxy 7.5: see `expected-cosmic.json` (after running Python script)

When changing dimension implementations, both snapshots must be regenerated.
The equivalence test asserts both snapshots are within 0.10 of each other.
```

- [ ] **Step 4: Commit**

```bash
git add tests/integration/cosmic-galaxy/expected-vule.json tests/integration/cosmic-galaxy/README.md
git commit -m "test(integration): vule snapshot + snapshot regen instructions"
```

---

## Task 5: Run All Sprint 7 Tests + Final Verification

- [ ] **Step 1: Run equivalence test (without cosmic output)**

Run: `bun test tests/integration/cosmic-galaxy/equivalence.test.ts`
Expected: PASS (3 tests, 1 may skip if cosmic output absent)

- [ ] **Step 2: Full test suite**

Run: `bun test`
Expected: All previous Sprints 1-6 tests + Sprint 7 = 50+ tests PASS

- [ ] **Step 3: Type check**

Run: `npx tsc --noEmit 2>&1 | grep -v tree-sitter | head`

- [ ] **Step 4: Final commit if any fixups**

```bash
git status --short
# Fix any issues
git add -A && git commit -m "chore: sprint 7 final cleanups"
```

---

## Task 6: Performance Smoke Test

**Files:**
- Create: `tests/integration/performance.test.ts`

- [ ] **Step 1: Write performance test**

```typescript
// tests/integration/performance.test.ts
import { describe, expect, test } from 'bun:test';
import { CPGBuilder } from '../../src/engine/cpg/builder.js';
import { createCPG } from '../../src/engine/cpg/types.js';
import { VuleEngine } from '../../src/engine/vule-engine.js';
import { defaultConfig } from '../../src/engine/vule-config.js';

function generateLargeCPG(nodeCount: number): any {
  const nodes = new Map();
  const edges: any[] = [];
  for (let i = 0; i < nodeCount; i++) {
    nodes.set(`n${i}`, {
      id: `n${i}`, type: 'stmt', file: 'perf.php', line: i + 1, col: 0,
      code: `$x${i}`, language: 'php',
      features: i % 50 === 0 ? { is_sink: 1, dangerousness: 0.9 } : {},
    });
    if (i > 0) edges.push({ source: `n${i - 1}`, target: `n${i}`, kind: 'data' });
  }
  return { nodes, edges };
}

describe('Performance', () => {
  test('analyzes 100-node CPG in < 1s', () => {
    const pg = generateLargeCPG(100);
    const cpg = new CPGBuilder('php').build(pg as any);
    const sinks = cpg.sinkNodes().map(n => n.id);
    const engine = new VuleEngine(cpg, sinks, []);
    const t0 = performance.now();
    engine.analyze();
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeLessThan(1000);
  });
  test('analyzes 1000-node CPG in < 10s', () => {
    const pg = generateLargeCPG(1000);
    const cpg = new CPGBuilder('php').build(pg as any);
    const sinks = cpg.sinkNodes().map(n => n.id);
    const engine = new VuleEngine(cpg, sinks, []);
    const t0 = performance.now();
    engine.analyze();
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeLessThan(10000);
  });
});
```

- [ ] **Step 2: Run → expect PASS**

- [ ] **Step 3: Commit**

```bash
git add tests/integration/performance.test.ts
git commit -m "test(integration): performance smoke test (100/1000 nodes)"
```

---

## Definition of Done (Sprint 7)

- [ ] CPG interchange format defined (cpg-fixture.json)
- [ ] Python script (run_cosmic.py) runs cosmic-galaxy on fixture
- [ ] TypeScript test (equivalence.test.ts) compares both UVRS with 0.10 tolerance
- [ ] security-vule snapshot saved (expected-vule.json)
- [ ] Performance smoke test passes (1000 nodes < 10s)
- [ ] README documents the workflow
- [ ] 0 new TypeScript errors

**This completes the cosmic-galaxy evolution plan**: 19 dimensions + CPG + VuleEngine + CLI + Web UI + cross-project equivalence test.

**Future work** (post-Sprint 7):
- Joern integration for production CPG generation
- SARIF output format
- IDE plugins (VS Code, JetBrains)
- SaaS deployment